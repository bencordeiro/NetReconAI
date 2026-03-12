from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ScanMode(str, Enum):
    host_discovery = "host_discovery"
    deep_scan = "deep_scan"
    vuln_scan = "vuln_scan"
    ping_probe = "ping_probe"
    tshark_capture = "tshark_capture"
    nslookup_query = "nslookup_query"
    traceroute_path = "traceroute_path"
    dig_query = "dig_query"
    whois_query = "whois_query"
    arp_scan = "arp_scan"
    curl_inspect = "curl_inspect"


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    mode: ScanMode
    interface: str | None = Field(default=None, max_length=64)
    packet_count: int = Field(default=100, ge=1, le=5000)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Target is required.")
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/:,")
        if any(ch not in allowed for ch in cleaned):
            raise ValueError("Target contains unsupported characters.")
        return cleaned

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:")
        if any(ch not in allowed for ch in cleaned):
            raise ValueError("Interface contains unsupported characters.")
        return cleaned


class ScanResult(BaseModel):
    command: list[str]
    stdout: str
    stderr: str
    exit_code: int
    started_at: str
    finished_at: str
    duration_seconds: float
    status: str


class JobRecord(BaseModel):
    job_id: str
    created_at: str
    request: ScanRequest
    result: ScanResult | None = None
    report_sections: dict[str, Any] = Field(default_factory=dict)
    report_metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def build(cls, job_id: str, request: ScanRequest) -> "JobRecord":
        now = datetime.now(timezone.utc).isoformat()
        return cls(job_id=job_id, created_at=now, request=request)
