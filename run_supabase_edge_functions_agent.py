#!/usr/bin/env python3
"""
OTVP Supabase Agent: Edge Function Security

Verifies Edge Function deployment security: JWT verification requirements,
public invokability settings, and function inventory.

Maps to SOC 2 CC6.1, CC6.6.

Usage:
    export SUPABASE_ACCESS_TOKEN=<personal-access-token>
    export SUPABASE_PROJECT_REF=<project-ref>
    python run_supabase_edge_functions_agent.py
"""
from __future__ import annotations

import asyncio
import argparse
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from otvp_agent import Agent, AgentConfig, Domain, Evidence, EvidenceType, KeyPair
from otvp_agent.agents import Collector, CollectionContext, EvaluationResult
from otvp_agent.agents.supabase.base import SupabaseEvaluator
from otvp_agent.agents.supabase.management import SupabaseManagementAPI
from otvp_agent.agents.supabase.constants import DOMAIN_EDGE_FUNCTIONS
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_edge_functions")


class EdgeFunctionCollector(Collector):
    domain = DOMAIN_EDGE_FUNCTIONS
    source_type = "management_api"
    provider = "supabase"

    def __init__(self, api: SupabaseManagementAPI | None = None) -> None:
        self.api: SupabaseManagementAPI | None = api

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        api = self.api
        if api is None:
            raise RuntimeError("EdgeFunctionCollector requires a SupabaseManagementAPI.")

        project_ref = api.project_ref
        functions = api.get_edge_functions()

        evidence_items: list[Evidence] = []

        if not functions:
            evidence_items.append(Evidence(
                evidence_type=EvidenceType.CONFIGURATION,
                domain=self.domain,
                source={
                    "provider": "supabase", "service": "edge_functions",
                    "resource_type": "function_inventory", "resource_id": "edge.inventory",
                    "project_ref": project_ref, "collection_method": "management_api",
                },
                observation={
                    "check": "edge_function_inventory",
                    "total_functions": 0,
                    "passed": True,
                    "severity": "none",
                    "detail": "No Edge Functions deployed.",
                },
                tags={"framework": "soc2", "criteria": "CC6.1,CC6.6", "agent": "supabase-edge-functions"},
            ))
            return evidence_items

        # Per-function analysis
        no_jwt_functions = []
        for fn in functions:
            name = fn.get("name", fn.get("slug", "unknown"))
            verify_jwt = fn.get("verify_jwt", True)
            status = fn.get("status", "unknown")

            risk_flags = []
            if not verify_jwt:
                risk_flags.append("jwt_verification_disabled")
                no_jwt_functions.append(name)

            passed = verify_jwt
            severity = "high" if not verify_jwt else "none"

            evidence_items.append(Evidence(
                evidence_type=EvidenceType.CONFIGURATION,
                domain=self.domain,
                source={
                    "provider": "supabase", "service": "edge_functions",
                    "resource_type": "edge_function", "resource_id": f"edge.function.{name}",
                    "project_ref": project_ref, "collection_method": "management_api",
                },
                observation={
                    "check": "edge_function_jwt",
                    "function_name": name,
                    "verify_jwt": verify_jwt,
                    "status": status,
                    "risk_flags": risk_flags,
                    "passed": passed,
                    "severity": severity,
                    "detail": (
                        f"Edge Function '{name}': JWT verification {'enabled' if verify_jwt else 'DISABLED — publicly invokable without auth'}."
                    ),
                },
                tags={"framework": "soc2", "criteria": "CC6.1,CC6.6", "agent": "supabase-edge-functions"},
            ))

        # Summary
        evidence_items.append(Evidence(
            evidence_type=EvidenceType.CONFIGURATION,
            domain=self.domain,
            source={
                "provider": "supabase", "service": "edge_functions",
                "resource_type": "function_summary", "resource_id": "edge.summary",
                "project_ref": project_ref, "collection_method": "management_api",
            },
            observation={
                "check": "edge_function_summary",
                "total_functions": len(functions),
                "no_jwt_count": len(no_jwt_functions),
                "no_jwt_functions": no_jwt_functions,
                "passed": len(no_jwt_functions) == 0,
                "severity": "high" if no_jwt_functions else "none",
                "detail": (
                    f"{len(functions)} Edge Function(s) deployed, "
                    f"{len(no_jwt_functions)} without JWT verification."
                ),
            },
            tags={"framework": "soc2", "criteria": "CC6.1,CC6.6", "agent": "supabase-edge-functions"},
        ))

        return evidence_items


class EdgeFunctionEvaluator(SupabaseEvaluator):
    domain = DOMAIN_EDGE_FUNCTIONS
    assertion = "All Supabase Edge Functions require JWT verification and follow least-privilege invocation patterns"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.INDETERMINATE, confidence=0.0,
                                    assessment="No Edge Function evidence collected.", evidence_ids=[])

        passed, failed = [], []
        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            if obs.get("passed", False):
                passed.append(obs.get("check", "?"))
            else:
                failed.append({"check": obs.get("check", "?"), "severity": obs.get("severity", "none"), "detail": obs.get("detail", "")})

        total = len(evidence_items)
        all_ids = [e.evidence_id for e in evidence_items]

        if len(passed) == total:
            return EvaluationResult(result=ClaimResult.SATISFIED, confidence=1.0,
                                    assessment=f"All {total} Edge Function checks pass.", evidence_ids=all_ids)
        if not passed:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=1.0,
                                    assessment=f"All {total} Edge Function checks have issues.",
                                    caveats=[f"{f['check']}: {f['detail']}" for f in failed],
                                    recommendations=[_edge_rec(f) for f in failed[:5]], evidence_ids=all_ids)

        confidence = round(len(passed) / total, 3)
        return EvaluationResult(result=ClaimResult.PARTIAL, confidence=confidence,
                                assessment=f"{len(passed)}/{total} Edge Function checks pass.",
                                caveats=[f"{f['check']} [{f['severity']}]: {f['detail']}" for f in failed],
                                recommendations=[_edge_rec(f) for f in failed[:5]], evidence_ids=all_ids)


def _edge_rec(f: dict) -> str:
    if f["check"] == "edge_function_jwt":
        return "Enable JWT verification on Edge Functions: supabase functions deploy <name> --no-verify-jwt=false"
    if f["check"] == "edge_function_summary":
        return "Review all Edge Functions without JWT verification. Public functions can be invoked by anyone without authentication."
    return f"Review: {f['detail']}"


class SupabaseEdgeFunctionAgent:
    def __init__(self, agent: Agent, api: SupabaseManagementAPI) -> None:
        self.agent = agent
        self.api = api
        self.collector = EdgeFunctionCollector()
        self.evaluator = EdgeFunctionEvaluator()

    @classmethod
    def create(cls, project_ref: str | None = None, access_token: str | None = None) -> SupabaseEdgeFunctionAgent:
        keys = KeyPair.generate()
        config = AgentConfig(agent_id="supabase-edge-functions-agent-v1", vendor="OTVP Reference / Killswitch Advisory",
                             version="1.0.0", key_pair=keys, domains=[Domain.EDGE_FUNCTIONS])
        return cls(agent=Agent(config), api=SupabaseManagementAPI(access_token=access_token, project_ref=project_ref))

    async def run(self, subject: str = "killswitch-advisory", relying_party: str | None = None) -> None:
        project_ref = self.api.project_ref or "(unknown)"
        print("=" * 70)
        print("  OTVP Supabase Agent: Edge Function Security")
        print(f"  Project: {project_ref}")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        self.collector.api = self.api
        ctx = CollectionContext(environment="production", custom={"project_ref": project_ref})
        evidence = await self.collector.collect(ctx)

        passed = sum(1 for e in evidence if isinstance(e.observation, dict) and e.observation.get("passed"))
        print(f"  Collected {len(evidence)} evidence items (passed: {passed}, failed: {len(evidence) - passed})")
        print()

        signed_refs = [self.agent.sign_evidence(ev).evidence_id for ev in evidence]
        result = await self.evaluator.evaluate(evidence)
        print(f"  Evaluation: {result.result.value}")
        print(f"  Confidence: {result.confidence:.0%}")
        print(f"  Assessment: {result.assessment}")
        for c in result.caveats: print(f"  ! {c}")
        for r in result.recommendations: print(f"  > {r}")
        print()

        claim = self.agent.create_claim(domain=DOMAIN_EDGE_FUNCTIONS, assertion=self.evaluator.assertion,
                                         result=result.result, confidence=result.confidence, evidence_refs=signed_refs,
                                         opinion=result.assessment, caveats=result.caveats, recommendations=result.recommendations,
                                         scope=ClaimScope(environment="production", services=["Supabase Edge Functions"], regions=[project_ref]))
        envelope = self.agent.build_envelope(claims=[claim], subject=subject, relying_party=relying_party)

        print("-" * 70)
        print(envelope.summary())
        print()
        print(envelope.to_json(indent=2))

        output_path = "supabase_edge_functions_envelope.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OTVP Supabase Edge Function Security Agent")
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    parser.add_argument("--project-ref", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    access_token = os.environ.get("SUPABASE_ACCESS_TOKEN", "")
    project_ref = args.project_ref or os.environ.get("SUPABASE_PROJECT_REF", "")
    if not access_token:
        print("ERROR: SUPABASE_ACCESS_TOKEN is required.", file=sys.stderr); sys.exit(1)
    if not project_ref:
        print("ERROR: SUPABASE_PROJECT_REF is required.", file=sys.stderr); sys.exit(1)
    agent = SupabaseEdgeFunctionAgent.create(project_ref=project_ref, access_token=access_token)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
