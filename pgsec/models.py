from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional
import time

REPORT_FIELDS = ["Status", "Name", "Description", "Test Result", "Solution", "Security Comments"]

@dataclass
class CommandResult:
    stdout: str = ""
    stderr: str = ""
    rc: int = 0
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.rc == 0

@dataclass
class Target:
    mode: str
    host: str = "local"
    port: int = 22
    username: Optional[str] = None
    auth_method: Optional[str] = None
    key_file: Optional[str] = None
    container_runtime: Optional[str] = None
    container_id: Optional[str] = None
    container_name: Optional[str] = None
    container_image: Optional[str] = None
    db_user: Optional[str] = None
    db_name: str = "postgres"

    def display_host(self) -> str:
        if (self.mode or "").startswith("local"):
            return "local"
        return self.host or "local"

    def label(self) -> str:
        base = self.display_host()
        if self.container_name or self.container_id:
            return f"{base}/{self.container_name or self.container_id}"
        return base

@dataclass
class Evidence:
    source: str
    detail: str
    command: str = ""
    rc: Optional[int] = None
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "Source": self.source,
            "Detail": self.detail,
            "Command": self.command,
            "Return Code": self.rc if self.rc is not None else "",
            "Timestamp": self.timestamp,
        }

@dataclass
class Result:
    status: str
    name: str
    description: str
    test_result: str
    solution: str
    security_comments: str
    control_id: str = ""
    source: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    required_input: str = ""

    def as_report_dict(self) -> dict[str, str]:
        return {
            "Status": self.status,
            "Name": self.name,
            "Description": self.description,
            "Test Result": self.test_result,
            "Solution": self.solution,
            "Security Comments": self.security_comments,
        }

    def as_json_dict(self) -> dict[str, Any]:
        d = {
            "control_id": self.control_id,
            "source": self.source,
            "status": self.status,
            "name": self.name,
            "description": self.description,
            "test_result": self.test_result,
            "solution": self.solution,
            "security_comments": self.security_comments,
            "required_input": self.required_input,
            "evidence": [e.as_dict() for e in self.evidence],
        }
        return d
