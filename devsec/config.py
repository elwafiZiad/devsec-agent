import hashlib
import json
import os
from pathlib import Path
import secrets

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"


def password_hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 260000).hex()


def settings():
    path = Path(os.environ.get("DEVSEC_CONFIG", LOCAL / "config.json"))
    if not path.exists():
        raise RuntimeError("Configuration absente : python -m devsec.setup")
    config = json.loads(path.read_text(encoding="utf-8"))
    config["database_url"] = os.environ.get("DATABASE_URL", config["database_url"])
    return config


def initialize():
    LOCAL.mkdir(parents=True, exist_ok=True)
    (LOCAL / "logs").mkdir(exist_ok=True)
    path = LOCAL / "config.json"
    if path.exists():
        return False
    password = secrets.token_urlsafe(16)
    salt = secrets.token_hex(16)
    dbpass = secrets.token_urlsafe(24)
    data = {
        "database_url": "sqlite:///" + (LOCAL / "events.db").as_posix(),
        "postgres_url": f"postgresql+psycopg://devsec:{dbpass}@127.0.0.1:55432/devsec",
        "admin_username": "admin", "password_salt": salt,
        "password_hash": password_hash(password, salt),
        "collector_token": secrets.token_urlsafe(32),
        "pseudonym_key": secrets.token_hex(32),
        "api_url": "http://127.0.0.1:8010",
        "demo_url": "http://127.0.0.1:8011",
        "log_file": str(LOCAL / "logs" / "demo.jsonl"),
        "collector_db": str(LOCAL / "collector.db"),
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    (ROOT / ".env").write_text(f"POSTGRES_PASSWORD={dbpass}\n", encoding="utf-8")
    (ROOT / "ACCESS_LOCAL.md").write_text(
        "# Accès au laboratoire local\n\n"
        "Ces identifiants sont propres à cette installation. Ne pas les publier.\n\n"
        "- Tableau de bord : http://127.0.0.1:8010\n"
        f"- Utilisateur : admin\n- Mot de passe : `{password}`\n\n"
        "- Application observée : http://127.0.0.1:8011\n"
        "- Compte fictif de démonstration : `etudiant` / `demo-lab`\n",
        encoding="utf-8",
    )
    return True
