"""At-least-once delivery with durable local spool and stable event identifiers."""
import json
import logging
import os
from pathlib import Path
import sqlite3
import time
import uuid
import httpx
from .config import settings
from .schemas import event_adapter

log = logging.getLogger("collector")


class Collector:
    def __init__(self, config, client=None):
        self.config = config
        self.path = Path(config["log_file"])
        Path(config["collector_db"]).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(config["collector_db"])
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS cursors (identity TEXT PRIMARY KEY, position INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS pending (id INTEGER PRIMARY KEY, event_id TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS quarantine (id INTEGER PRIMARY KEY, reason TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        """)
        self.client = client or httpx.Client(base_url=config["api_url"], timeout=10)
        self.headers = {"Authorization": "Bearer " + config["collector_token"]}

    def counts(self):
        return {"source": "demo-auth", "pending": self.db.execute("SELECT count(*) FROM pending").fetchone()[0],
                "quarantined": self.db.execute("SELECT count(*) FROM quarantine").fetchone()[0]}

    def scan(self):
        # Archives kept beside the active file permit rename rotation across restarts.
        files = sorted(self.path.parent.glob(self.path.name + ".*"))
        if self.path.exists():
            files.append(self.path)
        for path in files:
            if not path.is_file():
                continue
            with path.open("rb") as stream:
                stat = os.fstat(stream.fileno())
                identity = f"{stat.st_dev}:{stat.st_ino}"
                row = self.db.execute("SELECT position FROM cursors WHERE identity=?", (identity,)).fetchone()
                position = row[0] if row else 0
                if stat.st_size < position:
                    # copytruncate: read the new content; event IDs deduplicate old copies.
                    position = 0
                stream.seek(position)
                for _ in range(200):
                    raw = stream.readline(65537)
                    if not raw:
                        break
                    if not raw.endswith(b"\n") and len(raw) <= 65536:
                        break  # Wait for the writer to finish the line.
                    oversized = len(raw) > 65536
                    if oversized and not raw.endswith(b"\n"):
                        while True:
                            chunk = stream.readline(65537)
                            if not chunk or chunk.endswith(b"\n"):
                                break
                        # An incomplete oversized line is retried until complete.
                        if not chunk.endswith(b"\n"):
                            break
                    with self.db:
                        try:
                            if oversized:
                                raise ValueError("oversized")
                            data = event_adapter.validate_json(raw).model_dump(mode="json")
                            self.db.execute("INSERT INTO pending(event_id,payload) VALUES(?,?)", (data["event_id"], json.dumps(data)))
                        except (ValueError, UnicodeError):
                            # Never store raw rejected input: it may contain a secret.
                            self.db.execute("INSERT INTO quarantine(reason) VALUES(?)", ("invalid_or_oversized_line",))
                        self.db.execute("INSERT INTO cursors(identity,position) VALUES(?,?) ON CONFLICT(identity) DO UPDATE SET position=excluded.position", (identity, stream.tell()))

    def deliver(self):
        rows = self.db.execute("SELECT id,event_id,payload FROM pending ORDER BY id LIMIT 200").fetchall()
        if not rows:
            return
        # Keep the batch below the API body limit even for long request paths.
        size = 0
        for index, row in enumerate(rows):
            size += len(row[2]) + 2
            if size > 1_040_000:
                rows = rows[:index]
                break
        response = self.client.post("/events/batch", headers=self.headers, json={"batch_id": str(uuid.uuid4()), "events": [json.loads(r[2]) for r in rows]})
        response.raise_for_status()
        result = response.json()
        acknowledged = set(result.get("accepted", [])) | set(result.get("duplicates", []))
        rejected = {x["index"]: x["code"] for x in result.get("rejected", [])}
        with self.db:
            for index, row in enumerate(rows):
                if index in rejected:
                    self.db.execute("INSERT INTO quarantine(reason) VALUES(?)", (rejected[index],))
                    self.db.execute("DELETE FROM pending WHERE id=?", (row[0],))
                elif row[1] in acknowledged:
                    self.db.execute("DELETE FROM pending WHERE id=?", (row[0],))

    def tick(self):
        self.scan()
        self.deliver()
        response = self.client.post("/collectors/heartbeat", headers=self.headers, json=self.counts())
        response.raise_for_status()

    def close(self):
        self.db.close()
        self.client.close()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    collector = Collector(settings())
    log.info("Collecteur démarré ; intervalle 2 secondes")
    try:
        while True:
            try:
                collector.tick()
            except (httpx.HTTPError, OSError, ValueError):
                log.warning("Service inaccessible ou réponse invalide ; lot conservé pour reprise.")
            time.sleep(2)
    except KeyboardInterrupt:
        pass
    finally:
        collector.close()


if __name__ == "__main__":
    main()
