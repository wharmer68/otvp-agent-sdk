"""Agent Core — the main class for OTVP verification agents."""
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from otvp_agent.claims import Claim, ClaimResult, ClaimScope, Opinion
from otvp_agent.crypto.keys import KeyPair
from otvp_agent.domains import Domain
from otvp_agent.envelope import (DisclosureLevel, EvidenceSummary, RelyingPartyInfo,
                                  SubjectInfo, TrustEnvelope)
from otvp_agent.evidence.models import Evidence, SignedEvidence
from otvp_agent.evidence.store import EvidenceStore

logger = logging.getLogger("otvp.agent")


@dataclass
class AgentConfig:
    agent_id: str
    vendor: str
    version: str
    key_pair: KeyPair
    domains: list[Domain | str] = field(default_factory=list)
    certification_ref: str | None = None
    evidence_store_path: str | Path | None = None
    default_ttl_seconds: int = 3600
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def domain_paths(self) -> list[str]:
        return [d.value if isinstance(d, Domain) else d for d in self.domains]


class Agent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.evidence_store = EvidenceStore(persist_path=config.evidence_store_path)
        self._started_at = datetime.now(timezone.utc)

    @property
    def agent_id(self) -> str: return self.config.agent_id
    @property
    def version(self) -> str: return self.config.version
    @property
    def key_pair(self) -> KeyPair: return self.config.key_pair

    def sign_evidence(self, evidence: Evidence) -> SignedEvidence:
        signable = evidence.to_signable_dict()
        signature = self.key_pair.sign_json(signable)
        signed = SignedEvidence.from_evidence(
            ev=evidence, agent_id=self.config.agent_id,
            agent_version=self.config.version, signature=signature)
        self.evidence_store.append(signed)
        return signed

    def verify_evidence(self, signed: SignedEvidence) -> bool:
        if not signed.signature: return False
        return self.key_pair.verify_json(signed.signature, signed.to_verifiable_dict())

    def create_claim(self, domain: str, assertion: str, result: ClaimResult | str,
                     confidence: float, evidence_refs: list[str] | None = None,
                     opinion: str | None = None, opinion_context: str | None = None,
                     caveats: list[str] | None = None, recommendations: list[str] | None = None,
                     scope: ClaimScope | None = None, ttl_seconds: int | None = None) -> Claim:
        if isinstance(result, str): result = ClaimResult(result)
        opinion_obj = None
        if opinion:
            opinion_obj = Opinion(assessment=opinion, context=opinion_context,
                                  caveats=caveats or [], recommendations=recommendations or [])
        claim = Claim(
            domain=domain, assertion=assertion, result=result, confidence=confidence,
            evidence_refs=evidence_refs or [],
            evidence_count=len(evidence_refs) if evidence_refs else 0,
            opinion=opinion_obj, scope=scope or ClaimScope(),
            ttl_seconds=ttl_seconds or self.config.default_ttl_seconds,
            agent_id=self.config.agent_id, agent_version=self.config.version,
            agent_certification=self.config.certification_ref)
        claim.signature = self.key_pair.sign_json(claim.to_signable_dict())
        return claim

    def verify_claim(self, claim: Claim) -> bool:
        if claim.signature is None: return False
        return self.key_pair.verify_json(claim.signature, claim.to_signable_dict())

    def build_envelope(self, claims: list[Claim], subject: str | SubjectInfo,
                       relying_party: str | RelyingPartyInfo | None = None,
                       query_ref: str | None = None,
                       disclosure_level: DisclosureLevel = DisclosureLevel.CLAIMS_ONLY,
                       ttl_seconds: int | None = None) -> TrustEnvelope:
        if isinstance(subject, str):
            subject = SubjectInfo(organization=subject, otvp_id=f"otvp:org:{subject}")
        rp = None
        if isinstance(relying_party, str):
            rp = RelyingPartyInfo(organization=relying_party, otvp_id=f"otvp:org:{relying_party}")
        elif isinstance(relying_party, RelyingPartyInfo):
            rp = relying_party

        cs = self.evidence_store.export_chain_summary()
        ev_summary = EvidenceSummary(
            total_items=cs["total_items"], merkle_root=cs["merkle_root"],
            collection_window_start=cs["first_collected"],
            collection_window_end=cs["last_collected"],
            domains_covered=cs["domains_covered"])

        envelope = TrustEnvelope(
            subject=subject, relying_party=rp, query_ref=query_ref,
            disclosure_level=disclosure_level, claims=claims,
            evidence_summary=ev_summary,
            ttl_seconds=ttl_seconds or self.config.default_ttl_seconds)
        envelope.compute_scores()
        envelope.signer_id = self.config.agent_id
        envelope.signature = self.key_pair.sign_json(envelope.to_signable_dict())
        return envelope

    def verify_envelope(self, envelope: TrustEnvelope) -> bool:
        if envelope.signature is None: return False
        return self.key_pair.verify_json(envelope.signature, envelope.to_signable_dict())

    def status(self) -> dict:
        return {"agent_id": self.config.agent_id, "vendor": self.config.vendor,
                "version": self.config.version, "domains": self.config.domain_paths,
                "evidence_store": {"size": self.evidence_store.size, "merkle_root": self.evidence_store.root_hash},
                "public_key": self.key_pair.public_key_b64()}
