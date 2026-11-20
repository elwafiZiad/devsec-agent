from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, String, Integer, Text, UniqueConstraint, ForeignKey, event
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc).isoformat()


class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True)
    source = Column(String(64), nullable=False)
    external_id = Column(String(128), nullable=False)
    event_time = Column(String(40), nullable=False, index=True)
    received_at = Column(String(40), nullable=False)
    event_type = Column(String(64), nullable=False, index=True)
    outcome = Column(String(16), nullable=False)
    service = Column(String(64), nullable=False)
    payload = Column(Text, nullable=False)
    __table_args__ = (UniqueConstraint("source", "external_id", name="uq_source_event"),)


class LoginSession(Base):
    __tablename__ = "sessions"
    token_hash = Column(String(64), primary_key=True)
    expires_at = Column(String(40), nullable=False)


class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    rule = Column(String(16), nullable=False, index=True)
    entity_key = Column(String(64), nullable=False, index=True)
    user_id = Column(String(64), nullable=False)
    source_ip = Column(String(64), nullable=False)
    service = Column(String(64), nullable=False)
    environment = Column(String(32), nullable=False)
    severity = Column(String(16), nullable=False, default="medium")
    state = Column(String(24), nullable=False, default="new")
    started_at = Column(String(40), nullable=False)
    last_event_at = Column(String(40), nullable=False)
    detected_at = Column(String(40), nullable=False)
    updated_at = Column(String(40), nullable=False)
    peak_count = Column(Integer, nullable=False)


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    incident_id = Column(Integer, ForeignKey("incidents.id"), primary_key=True)
    event_id = Column(Integer, ForeignKey("events.id"), primary_key=True)


class CollectorStatus(Base):
    __tablename__ = "collector_status"
    source = Column(String(64), primary_key=True)
    last_seen_at = Column(String(40), nullable=False)
    pending = Column(Integer, nullable=False, default=0)
    quarantined = Column(Integer, nullable=False, default=0)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    key = Column(String(64), primary_key=True)
    count = Column(Integer, nullable=False, default=0)
    window_start = Column(String(40), nullable=False)


def database(url):
    engine = create_engine(url, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {}, pool_pre_ping=True)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def configure(connection, _):
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=5000")
    # Initial schema only; future evolution requires migrations, never drop_all.
    Base.metadata.create_all(engine)
    return engine, sessionmaker(engine, expire_on_commit=False)
