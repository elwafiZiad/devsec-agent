"""Weekly planning for demo-app in the lab. ISO weekday 1 is Monday."""
import hashlib
import hmac
import json
from datetime import datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo


def account_id(config, name):
    digest = hmac.new(bytes.fromhex(config["pseudonym_key"]), name.encode(), hashlib.sha256)
    return "usr-" + digest.hexdigest()[:24]


class Schedules:
    def __init__(self, config):
        path = Path(config.get("schedule_file", Path(__file__).with_name("schedules.json")))
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        self.zone = ZoneInfo(data["timezone"])
        self.accounts = {account_id(config, name): slots for name, slots in data["accounts"].items()}
        self.members = {account_id(config, name) for name in data["service_accounts"]}
        self.service_slots = data["service_slots"]
        for slots in [*self.accounts.values(), self.service_slots]:
            for slot in slots:
                if not set(slot["days"]).issubset(range(1, 8)) or not slot["days"]:
                    raise ValueError("Les jours du planning doivent être compris entre 1 et 7")
                for key in ("start", "end"):
                    time.fromisoformat(slot[key])
                if slot["start"] == slot["end"]:
                    raise ValueError("Le créneau doit avoir une durée explicite")

    def assess(self, event):
        user = event["user_id"]
        slots = self.accounts.get(user)
        source = "compte"
        if slots is None and user in self.members:
            slots, source = self.service_slots, "service"
        if slots is None or (event["service"], event["environment"]) != ("demo-app", "lab"):
            return {"status": "Horaire inconnu"}
        local = datetime.fromisoformat(event["event_time"].replace("Z", "+00:00")).astimezone(self.zone)
        day, clock = local.isoweekday(), local.time()
        inside = False
        for slot in slots:
            start, end = time.fromisoformat(slot["start"]), time.fromisoformat(slot["end"])
            if start < end:
                inside = day in slot["days"] and start <= clock < end
            else:
                previous = (day - 2) % 7 + 1
                inside = (day in slot["days"] and clock >= start) or (previous in slot["days"] and clock < end)
            if inside:
                break
        return {"status": "Dans le créneau" if inside else "Hors planning", "source": source,
                "timezone": self.zone.key, "local_time": local.isoformat(), "slots": slots}
