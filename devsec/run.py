"""Run all three local processes; PostgreSQL mode also starts the database container."""
import argparse
import json
import os
import socket
import subprocess
import sys
import time
from urllib.request import urlopen
from urllib.error import URLError
from .config import ROOT, LOCAL, initialize, settings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", choices=["sqlite", "postgres"], default="postgres")
    args = parser.parse_args()
    initialize()
    for port in (8010, 8011):
        with socket.socket() as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                raise SystemExit(f"Port {port} déjà utilisé. Arrêter l’instance existante avant de relancer.")
    config = settings()
    env = dict(os.environ)
    if args.database == "postgres":
        subprocess.run(["docker", "compose", "up", "-d", "--wait"], cwd=ROOT, check=True)
        env["DATABASE_URL"] = config["postgres_url"]
    else:
        env["DATABASE_URL"] = "sqlite:///" + (LOCAL / "events.db").as_posix()
    from .database import database
    schema_engine, _ = database(env["DATABASE_URL"])
    schema_engine.dispose()
    commands = [
        [sys.executable, "-m", "uvicorn", "devsec.api:create_app", "--factory", "--host", "127.0.0.1", "--port", "8010"],
        [sys.executable, "-m", "uvicorn", "devsec.demo:create_demo", "--factory", "--host", "127.0.0.1", "--port", "8011", "--no-access-log", "--no-proxy-headers"],
        [sys.executable, "-m", "devsec.collector"],
        [sys.executable, "-m", "devsec.rules"],
    ]
    children, streams = [], []
    try:
        for name, command in zip(["api", "demo", "collector", "rules"], commands):
            stream = (LOCAL / f"{name}.log").open("a", encoding="utf-8")
            streams.append(stream)
            children.append(subprocess.Popen(command, cwd=ROOT, env=env, stdout=stream, stderr=stream))
        (LOCAL / "processes.json").write_text(json.dumps({"supervisor": os.getpid(), "children": [p.pid for p in children]}), encoding="utf-8")
        deadline = time.monotonic() + 30
        while True:
            try:
                for url in (config["api_url"], config["demo_url"]):
                    with urlopen(url + "/health", timeout=2) as response:
                        if response.status != 200:
                            raise OSError("Service en cours de démarrage")
                break
            except (URLError, OSError):
                if time.monotonic() > deadline or any(p.poll() is not None for p in children):
                    raise RuntimeError("Démarrage incomplet. Consulter .local/*.log.")
                time.sleep(0.5)
        print("Tableau de bord : http://127.0.0.1:8010", flush=True)
        print("Application de test : http://127.0.0.1:8011", flush=True)
        print(f"Stockage : {args.database}. Accès dans ACCESS_LOCAL.md. Ctrl+C pour arrêter.", flush=True)
        while True:
            for process in children:
                if process.poll() is not None:
                    raise RuntimeError("Un service s’est arrêté. Consulter les fichiers .local/*.log.")
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for process in children:
            if process.poll() is None:
                process.terminate()
        for process in children:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        for stream in streams:
            stream.close()


if __name__ == "__main__":
    main()
