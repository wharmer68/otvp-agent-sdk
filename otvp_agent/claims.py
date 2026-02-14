"""Claims — an agent's assertion about a control, backed by evidence and opinion."""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class ClaimResult(str, Enum):
    SATISFIED = "SATISFIED"
    NOT_SATISFIED = "NOT_SATISFIED"
    PARTIAL = "PARTIAL"
    INDETERMINATE = "INDETERMINATE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class Opinion:
    assessment: str
    context: str | None = None
    caveats: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    def to_dict(self) -> dict:
        return {"assessment": self.assessment, "context": self.context,
                "caveats": self.caveats, "recommendations": self.recommendations}


@dataclass
class ClaimScope:
    environment: str | None = None
    services: list[str] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    def to_dict(self) -> dict:
        return {"environment": self.environment, "services": self.services,
                "regions": self.regions, "accounts": self.accounts,
                "exclusions": self.exclusions}


@dataclass
class Claim:
    domain: str
    assertion: str
    result: ClaimResult
    confidence: float
    claim_id: str = field(default_factory=lambda: f"cl-{uuid.uuid4().hex[:12]}")
    evidence_refs: list[str] = field(default_factory=list)
    evidence_count: int = 0
    opinion: Opinion | None = None
    scope: ClaimScope = field(default_factory=ClaimScope)
    valid_from: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ttl_seconds: int = 3600
    agent_id: str = ""
    agent_version: str = ""
    agent_certification: str | None = None
    signature: str | None = None

    @property
    def is_valid(self) -> bool:
        vf = datetime.fromisoformat(self.valid_from)
        return datetime.now(timezone.utc) < vf + timedelta(seconds=self.ttl_seconds)

    def to_signable_dict(self) -> dict:
        return {
            "claim_id": self.claim_id, "domain": self.domain, "assertion": self.assertion,
            "result": self.result.value if isinstance(self.result, Enum) else self.result,
            "confidence": self.confidence, "evidence_refs": self.evidence_refs,
            "evidence_count": self.evidence_count,
            "opinion": self.opinion.to_dict() if self.opinion else None,
            "scope": self.scope.to_dict(), "valid_from": self.valid_from,
            "ttl_seconds": self.ttl_seconds, "agent_id": self.agent_id,
            "agent_version": self.agent_version, "agent_certification": self.agent_certification,
        }

    def to_dict(self) -> dict:
        d = self.to_signable_dict()
        d["signature"] = self.signature
        return d
