"""Trust Envelope — the core deliverable of OTVP. Replaces SOC 2 reports."""
from __future__ import annotations
import json, uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
from otvp_agent.claims import Claim, ClaimResult


class DisclosureLevel(str, Enum):
    FULL = "full"
    CLAIMS_ONLY = "claims_only"
    ZERO_KNOWLEDGE = "zero_knowledge"


class TrustLevel(str, Enum):
    CRITICAL = "CRITICAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERIFIED = "VERIFIED"

    @classmethod
    def from_score(cls, score: float) -> TrustLevel:
        if score >= 0.95: return cls.VERIFIED
        if score >= 0.75: return cls.HIGH
        if score >= 0.55: return cls.MEDIUM
        if score >= 0.30: return cls.LOW
        return cls.CRITICAL


@dataclass
class SubjectInfo:
    organization: str
    otvp_id: str | None = None
    environment: str = "production"
    def to_dict(self) -> dict:
        return {"organization": self.organization, "otvp_id": self.otvp_id, "environment": self.environment}


@dataclass
class RelyingPartyInfo:
    organization: str
    otvp_id: str | None = None
    context: dict[str, Any] = field(default_factory=dict)
    def to_dict(self) -> dict:
        return {"organization": self.organization, "otvp_id": self.otvp_id, "context": self.context}


@dataclass
class DomainScore:
    level: TrustLevel
    confidence: float
    claims_satisfied: int = 0
    claims_total: int = 0
    def to_dict(self) -> dict:
        return {"level": self.level.value, "confidence": self.confidence,
                "claims_satisfied": self.claims_satisfied, "claims_total": self.claims_total}


@dataclass
class EvidenceSummary:
    total_items: int = 0
    merkle_root: str | None = None
    collection_window_start: str | None = None
    collection_window_end: str | None = None
    domains_covered: list[str] = field(default_factory=list)
    def to_dict(self) -> dict:
        return {"total_items": self.total_items, "merkle_root": self.merkle_root,
                "collection_window_start": self.collection_window_start,
                "collection_window_end": self.collection_window_end,
                "domains_covered": self.domains_covered}


@dataclass
class TrustEnvelope:
    subject: SubjectInfo
    envelope_id: str = field(default_factory=lambda: f"te-{uuid.uuid4().hex[:12]}")
    schema_version: str = "1.0"
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    valid_until: str | None = None
    ttl_seconds: int = 3600
    relying_party: RelyingPartyInfo | None = None
    query_ref: str | None = None
    disclosure_level: DisclosureLevel = DisclosureLevel.CLAIMS_ONLY
    claims: list[Claim] = field(default_factory=list)
    evidence_summary: EvidenceSummary = field(default_factory=EvidenceSummary)
    composite_level: TrustLevel | None = None
    domain_scores: dict[str, DomainScore] = field(default_factory=dict)
    signer_id: str | None = None
    signature: str | None = None

    def __post_init__(self):
        if self.valid_until is None:
            ga = datetime.fromisoformat(self.generated_at)
            self.valid_until = (ga + timedelta(seconds=self.ttl_seconds)).isoformat()

    @property
    def is_valid(self) -> bool:
        if self.valid_until is None: return True
        return datetime.now(timezone.utc) < datetime.fromisoformat(self.valid_until)

    def compute_scores(self) -> None:
        if not self.claims:
            self.composite_level = TrustLevel.CRITICAL
            return
        domain_claims: dict[str, list[Claim]] = {}
        for claim in self.claims:
            parts = claim.domain.split(".")
            key = ".".join(parts[:2]) if len(parts) >= 2 else claim.domain
            domain_claims.setdefault(key, []).append(claim)

        all_scores = []
        for domain_key, claims in domain_claims.items():
            satisfied = sum(1 for c in claims if c.result == ClaimResult.SATISFIED)
            total = len(claims)
            avg_conf = sum(c.confidence for c in claims) / total
            score = (satisfied / total) * avg_conf
            all_scores.append(score)
            self.domain_scores[domain_key] = DomainScore(
                level=TrustLevel.from_score(score), confidence=avg_conf,
                claims_satisfied=satisfied, claims_total=total)

        composite = sum(all_scores) / len(all_scores) if all_scores else 0
        self.composite_level = TrustLevel.from_score(composite)

    def to_signable_dict(self) -> dict:
        return {
            "envelope_id": self.envelope_id, "schema_version": self.schema_version,
            "generated_at": self.generated_at, "valid_until": self.valid_until,
            "ttl_seconds": self.ttl_seconds,
            "subject": self.subject.to_dict(),
            "relying_party": self.relying_party.to_dict() if self.relying_party else None,
            "query_ref": self.query_ref, "disclosure_level": self.disclosure_level.value,
            "claims": [c.to_dict() for c in self.claims],
            "evidence_summary": self.evidence_summary.to_dict(),
            "composite_level": self.composite_level.value if self.composite_level else None,
            "domain_scores": {k: v.to_dict() for k, v in self.domain_scores.items()},
        }

    def to_json(self, indent: int = 2) -> str:
        d = self.to_signable_dict()
        d["signer_id"] = self.signer_id
        d["signature"] = self.signature
        return json.dumps(d, indent=indent, default=str)

    def summary(self) -> str:
        lines = [f"Trust Envelope: {self.envelope_id}",
                 f"  Subject: {self.subject.organization}",
                 f"  Generated: {self.generated_at}",
                 f"  Valid Until: {self.valid_until}",
                 f"  Composite Trust: {self.composite_level.value if self.composite_level else 'N/A'}",
                 f"  Claims: {len(self.claims)}",
                 f"  Evidence Items: {self.evidence_summary.total_items}",
                 f"  Merkle Root: {self.evidence_summary.merkle_root or 'N/A'}"]
        for domain, score in self.domain_scores.items():
            lines.append(f"  [{domain}] {score.level.value} ({score.claims_satisfied}/{score.claims_total} satisfied, conf={score.confidence:.1%})")
        for claim in self.claims:
            lines.append(f"  Claim [{claim.claim_id}]: {claim.result.value} @ {claim.confidence:.0%} — {claim.assertion}")
            if claim.opinion:
                lines.append(f"    Opinion: {claim.opinion.assessment}")
                for caveat in claim.opinion.caveats:
                    lines.append(f"    Caveat: {caveat}")
        return "\n".join(lines)
