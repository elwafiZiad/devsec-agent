from datetime import datetime, timezone
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator, TypeAdapter, model_validator
import ipaddress


class BaseEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"]
    event_id: str = Field(min_length=1, max_length=128)
    event_time: datetime
    service: Literal["demo-app"]
    environment: Literal["lab"]
    source_ip: str
    request_id: str = Field(min_length=1, max_length=128)
    synthetic: Literal[True]

    @field_validator("event_time")
    @classmethod
    def timestamp(cls, value):
        if value.tzinfo is None:
            raise ValueError("Fuseau horaire obligatoire")
        return value.astimezone(timezone.utc)

    @field_validator("source_ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ipaddress.ip_address(value))


class AuthEvent(BaseEvent):
    source: Literal["demo-auth"]
    event_type: Literal["auth.failure", "auth.success"]
    user_id: str = Field(pattern=r"^usr-[0-9a-f]{24}$")
    session_id: None = None
    outcome: Literal["failure", "success"]
    raw_redacted: Literal["authentication failed", "authentication succeeded"]

    @model_validator(mode="after")
    def consistent_result(self):
        expected = "authentication failed" if self.outcome == "failure" else "authentication succeeded"
        if self.event_type != "auth." + self.outcome or self.raw_redacted != expected:
            raise ValueError("Résultat incohérent")
        return self


class AccessEvent(BaseEvent):
    source: Literal["demo-http"]
    event_type: Literal["http.access"]
    method: str = Field(pattern=r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
    path: str = Field(pattern=r"^/[^?#\x00-\x20\x7f]*$")
    status_code: int = Field(strict=True, ge=100, le=599)


class AuditEvent(BaseEvent):
    source: Literal["demo-audit"]
    user_id: str = Field(pattern=r"^usr-[0-9a-f]{24}$")


class RoleChange(AuditEvent):
    event_type: Literal["audit.role_change"]
    old_role: Literal["user", "admin"]
    new_role: Literal["user", "admin"]

    @model_validator(mode="after")
    def changed(self):
        if self.old_role == self.new_role:
            raise ValueError("Rôle inchangé")
        return self


class SensitiveAction(AuditEvent):
    event_type: Literal["audit.sensitive_action"]
    role: Literal["admin"]
    operation: Literal["settings.update"]


class MaintenanceWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service: Literal["demo-app"]
    environment: Literal["lab"]
    user_id: str = Field(pattern=r"^usr-[0-9a-f]{24}$")
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def valid_period(self):
        if self.start.tzinfo is None or self.end.tzinfo is None or self.end <= self.start:
            raise ValueError("Période de maintenance invalide")
        return self


Operation = Literal["service.restart", "settings.update"]


class TaskGrant(AuditEvent):
    event_type: Literal["audit.task_granted"]
    granted_by: str = Field(pattern=r"^usr-[0-9a-f]{24}$")
    operation: Operation
    resource: Literal["demo-worker", "demo-api"]
    expires_at: datetime

    @model_validator(mode="after")
    def valid_grant(self):
        if self.expires_at.tzinfo is None or self.expires_at <= self.event_time:
            raise ValueError("Échéance invalide")
        return self


class TaskAction(AuditEvent):
    event_type: Literal["audit.task_action"]
    operation: Operation
    resource: Literal["demo-worker", "demo-api"]
    result: Literal["executed", "denied"]


event_adapter = TypeAdapter(Annotated[AuthEvent | AccessEvent | RoleChange | SensitiveAction | TaskGrant | TaskAction, Field(discriminator="event_type")])


class Batch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    batch_id: str = Field(min_length=1, max_length=128)
    events: list[dict] = Field(min_length=1, max_length=200)


class Heartbeat(BaseModel):
    source: Literal["demo-auth"] = "demo-auth"
    pending: int = Field(ge=0)
    quarantined: int = Field(ge=0)
