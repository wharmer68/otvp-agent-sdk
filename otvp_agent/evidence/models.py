"""Evidence models — the atomic unit of OTVP."""
from __future__ import annotations
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EvidenceType(str, Enum):
    OBSERVATION = "OBSERVATION"
    LOG_SAMPLE = "LOG_SAMPLE"
    POLICY_SNAPSHOT = "POLICY_SNAPSHOT"
    RUNTIME_CHECK = "RUNTIME_CHECK"
    BEHAVIORAL = "BEHAVIORAL"
    ATTESTATION = "ATTESTATION"
    DERIVED = "DERIVED"


@dataclass
class Evidence:
    evidence_type: EvidenceType
    domain: str
    source: dict[str, Any]
    observation: dict[str, Any]
    evidence_id: str = field(default_factory=lambda: f"ev-{uuid.uuid4().hex[:12]}")
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    collection_duration_ms: int | None = None
    tags: dict[str, str] = field(default_factory=dict)

    def to_signable_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type.value if isinstance(self.evidence_type, Enum) else self.evidence_type,
            "domain": self.domain,
            "source": self.source,
            "observation": self.observation,
            "collected_at": self.collected_at,
            "collection_duration_ms": self.collection_duration_ms,
            "tags": self.tags,
        }


@dataclass
class SignedEvidence:
    evidence_id: str
    evidence_type: str
    domain: str
    source: dict[str, Any]
    observation: dict[str, Any]
    collected_at: str
    agent_id: str = ""
    agent_version: str = ""
    signature: str = ""
    collection_duration_ms: int | None = None
    tags: dict[str, str] = field(default_factory=dict)
    chain_previous_hash: str | None = None
    chain_sequence: int = 0
    chain_leaf_hash: str | None = None

    @classmethod
    def from_evidence(cls, ev: Evidence, agent_id: str, agent_version: str, signature: str) -> SignedEvidence:
        et = ev.evidence_type
        return cls(
            evidence_id=ev.evidence_id,
            evidence_type=et.value if isinstance(et, Enum) else et,
            domain=ev.domain, source=ev.source, observation=ev.observation,
            collected_at=ev.collected_at, collection_duration_ms=ev.collection_duration_ms,
            tags=ev.tags, agent_id=agent_id, agent_version=agent_version, signature=signature,
        )

    def to_verifiable_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id, "evidence_type": self.evidence_type,
            "domain": self.domain, "source": self.source, "observation": self.observation,
            "collected_at": self.collected_at, "collection_duration_ms": self.collection_duration_ms,
            "tags": self.tags,
        }

    def to_dict(self) -> dict:
        d = self.to_verifiable_dict()
        d.update({"agent_id": self.agent_id, "agent_version": self.agent_version,
                   "signature": self.signature, "chain_previous_hash": self.chain_previous_hash,
                   "chain_sequence": self.chain_sequence, "chain_leaf_hash": self.chain_leaf_hash})
        return d
