"""Agent building blocks — Collectors and Evaluators."""
from __future__ import annotations
import abc
from dataclasses import dataclass, field
from typing import Any
from otvp_agent.claims import ClaimResult, ClaimScope
from otvp_agent.evidence.models import Evidence, EvidenceType


@dataclass
class CollectionContext:
    environment: str = "production"
    region: str | None = None
    accounts: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    custom: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvaluationResult:
    result: ClaimResult
    confidence: float
    assessment: str
    caveats: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    scope: ClaimScope = field(default_factory=ClaimScope)
    evidence_ids: list[str] = field(default_factory=list)


class Collector(abc.ABC):
    domain: str = ""
    source_type: str = "cloud_api"
    provider: str | None = None

    @abc.abstractmethod
    async def collect(self, context: CollectionContext) -> list[Evidence]:
        ...

    def observe(self, resource: str, property: str, value: Any,
                expected: Any = None, metadata: dict | None = None,
                api: str | None = None, region: str | None = None) -> Evidence:
        return Evidence(
            evidence_type=EvidenceType.OBSERVATION, domain=self.domain,
            source={"type": self.source_type, "provider": self.provider, "api": api, "region": region},
            observation={"resource": resource, "property": property, "value": value,
                         "expected": expected, "metadata": metadata or {}},
        )


class Evaluator(abc.ABC):
    domain: str = ""
    assertion: str = ""

    @abc.abstractmethod
    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        ...


class BooleanEvaluator(Evaluator):
    property_name: str = ""
    expected_value: bool = True

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(
                result=ClaimResult.INDETERMINATE, confidence=0.0,
                assessment=f"No evidence collected for {self.domain}")

        matching, non_matching = [], []
        for item in evidence_items:
            val = item.observation.get("value") if isinstance(item.observation, dict) else None
            (matching if val == self.expected_value else non_matching).append(item)

        total = len(evidence_items)
        pct = len(matching) / total

        if pct == 1.0:
            return EvaluationResult(
                result=ClaimResult.SATISFIED, confidence=1.0,
                assessment=f"All {total} resource(s) verified: {self.property_name} = {self.expected_value}. 100% of population scanned.",
                evidence_ids=[e.evidence_id for e in evidence_items])
        elif pct >= 0.5:
            return EvaluationResult(
                result=ClaimResult.PARTIAL, confidence=round(pct, 3),
                assessment=f"{len(matching)}/{total} resources satisfy {self.property_name}. {len(non_matching)} non-compliant.",
                caveats=[f"{len(non_matching)} resource(s) non-compliant: " +
                         ", ".join(e.observation.get("resource", "?") if isinstance(e.observation, dict) else "?"
                                  for e in non_matching)],
                evidence_ids=[e.evidence_id for e in evidence_items])
        else:
            return EvaluationResult(
                result=ClaimResult.NOT_SATISFIED, confidence=1.0,
                assessment=f"Only {len(matching)}/{total} meet {self.property_name} = {self.expected_value}. {len(non_matching)} non-compliant.",
                caveats=[f"{len(non_matching)} resource(s) non-compliant"],
                evidence_ids=[e.evidence_id for e in evidence_items])
