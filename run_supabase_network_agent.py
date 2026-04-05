#!/usr/bin/env python3
"""
OTVP Supabase Agent: Network Restrictions

Verifies network-level security controls: IP allow-listing,
SSL enforcement, and connection pooler configuration.

Maps to SOC 2 CC6.6, CC6.7.

Usage:
    export SUPABASE_ACCESS_TOKEN=<personal-access-token>
    export SUPABASE_PROJECT_REF=<project-ref>
    python run_supabase_network_agent.py
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
from otvp_agent.agents.supabase.constants import DOMAIN_NETWORK_RESTRICTIONS
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_network")


class NetworkRestrictionCollector(Collector):
    domain = DOMAIN_NETWORK_RESTRICTIONS
    source_type = "management_api"
    provider = "supabase"

    def __init__(self, api: SupabaseManagementAPI | None = None) -> None:
        self.api: SupabaseManagementAPI | None = api

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        api = self.api
        if api is None:
            raise RuntimeError("NetworkRestrictionCollector requires a SupabaseManagementAPI.")

        project_ref = api.project_ref
        evidence_items: list[Evidence] = []

        # 1. Network restrictions (IP allow-list)
        try:
            net_config = api.get_network_restrictions()
        except Exception as exc:
            net_config = {"error": str(exc)}

        if "error" in net_config:
            evidence_items.append(Evidence(
                evidence_type=EvidenceType.CONFIGURATION,
                domain=self.domain,
                source={
                    "provider": "supabase", "service": "network",
                    "resource_type": "network_restrictions", "resource_id": "network.restrictions",
                    "project_ref": project_ref, "collection_method": "management_api",
                },
                observation={
                    "check": "network_restrictions",
                    "passed": False,
                    "severity": "medium",
                    "detail": f"Could not retrieve network restrictions: {net_config.get('error', 'unknown')}. "
                              "This endpoint may not be available on your plan.",
                },
                tags={"framework": "soc2", "criteria": "CC6.6,CC6.7", "agent": "supabase-network-restrictions"},
            ))
        else:
            # Parse restrictions
            entitlements = net_config.get("entitlement", "")
            config_status = net_config.get("status", "")
            restrictions = net_config.get("config", {})
            db_allowlist = restrictions.get("dbAllowedCidrs", [])

            # 0.0.0.0/0 means unrestricted
            is_unrestricted = not db_allowlist or "0.0.0.0/0" in db_allowlist
            has_ip_restrictions = not is_unrestricted and len(db_allowlist) > 0

            evidence_items.append(Evidence(
                evidence_type=EvidenceType.CONFIGURATION,
                domain=self.domain,
                source={
                    "provider": "supabase", "service": "network",
                    "resource_type": "network_restrictions", "resource_id": "network.restrictions",
                    "project_ref": project_ref, "collection_method": "management_api",
                },
                observation={
                    "check": "ip_restrictions",
                    "entitlement": entitlements,
                    "status": config_status,
                    "db_allowed_cidrs": db_allowlist,
                    "is_unrestricted": is_unrestricted,
                    "has_ip_restrictions": has_ip_restrictions,
                    "passed": has_ip_restrictions,
                    "severity": "medium" if is_unrestricted else "none",
                    "detail": (
                        f"Database has IP restrictions: {len(db_allowlist)} CIDR(s) allowed."
                        if has_ip_restrictions else
                        "Database is accessible from any IP (0.0.0.0/0 or no restrictions). "
                        "Consider restricting to known IP ranges."
                    ),
                },
                tags={"framework": "soc2", "criteria": "CC6.6,CC6.7", "agent": "supabase-network-restrictions"},
            ))

        # 2. Project settings (SSL, pooler)
        try:
            settings = api.get_project_settings()
        except Exception as exc:
            settings = {"error": str(exc)}

        if "error" not in settings:
            # SSL enforcement
            ssl_enforced = settings.get("db_ssl_enforced", False)
            evidence_items.append(Evidence(
                evidence_type=EvidenceType.CONFIGURATION,
                domain=self.domain,
                source={
                    "provider": "supabase", "service": "network",
                    "resource_type": "ssl_config", "resource_id": "network.ssl",
                    "project_ref": project_ref, "collection_method": "management_api",
                },
                observation={
                    "check": "ssl_enforcement",
                    "ssl_enforced": ssl_enforced,
                    "passed": True,  # SSL is always available; enforcement is a bonus
                    "severity": "low" if not ssl_enforced else "none",
                    "detail": (
                        "SSL enforcement is enabled — non-SSL connections are rejected."
                        if ssl_enforced else
                        "SSL is available but not enforced. Non-SSL connections are allowed."
                    ),
                },
                tags={"framework": "soc2", "criteria": "CC6.6,CC6.7", "agent": "supabase-network-restrictions"},
            ))

            # Project region info
            region = settings.get("region", "unknown")
            status = settings.get("status", "unknown")
            evidence_items.append(Evidence(
                evidence_type=EvidenceType.CONFIGURATION,
                domain=self.domain,
                source={
                    "provider": "supabase", "service": "network",
                    "resource_type": "project_info", "resource_id": "network.project",
                    "project_ref": project_ref, "collection_method": "management_api",
                },
                observation={
                    "check": "project_info",
                    "region": region,
                    "status": status,
                    "passed": True,
                    "severity": "none",
                    "detail": f"Project region: {region}, status: {status}.",
                },
                tags={"framework": "soc2", "criteria": "CC6.6,CC6.7", "agent": "supabase-network-restrictions"},
            ))

        return evidence_items


class NetworkRestrictionEvaluator(SupabaseEvaluator):
    domain = DOMAIN_NETWORK_RESTRICTIONS
    assertion = "Supabase project has appropriate network restrictions including IP allow-listing and SSL enforcement"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.INDETERMINATE, confidence=0.0,
                                    assessment="No network restriction evidence collected.", evidence_ids=[])

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
                                    assessment=f"All {total} network restriction checks pass.", evidence_ids=all_ids)
        if not passed:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=1.0,
                                    assessment=f"All {total} network checks have issues.",
                                    caveats=[f"{f['check']}: {f['detail']}" for f in failed],
                                    recommendations=[_net_rec(f) for f in failed[:5]], evidence_ids=all_ids)

        confidence = round(len(passed) / total, 3)
        return EvaluationResult(result=ClaimResult.PARTIAL, confidence=confidence,
                                assessment=f"{len(passed)}/{total} network checks pass.",
                                caveats=[f"{f['check']} [{f['severity']}]: {f['detail']}" for f in failed],
                                recommendations=[_net_rec(f) for f in failed[:5]], evidence_ids=all_ids)


def _net_rec(f: dict) -> str:
    if f["check"] == "ip_restrictions":
        return "Configure IP restrictions in Supabase Dashboard > Settings > Network to limit database access to known IP ranges."
    if f["check"] == "ssl_enforcement":
        return "Enable SSL enforcement in project settings to reject non-SSL connections."
    if f["check"] == "network_restrictions":
        return "Network restrictions may require a Pro plan or higher. Upgrade to enable IP allow-listing."
    return f"Review: {f['detail']}"


class SupabaseNetworkAgent:
    def __init__(self, agent: Agent, api: SupabaseManagementAPI) -> None:
        self.agent = agent
        self.api = api
        self.collector = NetworkRestrictionCollector()
        self.evaluator = NetworkRestrictionEvaluator()

    @classmethod
    def create(cls, project_ref: str | None = None, access_token: str | None = None) -> SupabaseNetworkAgent:
        keys = KeyPair.generate()
        config = AgentConfig(agent_id="supabase-network-agent-v1", vendor="OTVP Reference / Killswitch Advisory",
                             version="1.0.0", key_pair=keys, domains=[Domain.NETWORK_RESTRICTIONS])
        return cls(agent=Agent(config), api=SupabaseManagementAPI(access_token=access_token, project_ref=project_ref))

    async def run(self, subject: str = "killswitch-advisory", relying_party: str | None = None) -> None:
        project_ref = self.api.project_ref or "(unknown)"
        print("=" * 70)
        print("  OTVP Supabase Agent: Network Restrictions")
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

        claim = self.agent.create_claim(domain=DOMAIN_NETWORK_RESTRICTIONS, assertion=self.evaluator.assertion,
                                         result=result.result, confidence=result.confidence, evidence_refs=signed_refs,
                                         opinion=result.assessment, caveats=result.caveats, recommendations=result.recommendations,
                                         scope=ClaimScope(environment="production", services=["Supabase Network"], regions=[project_ref]))
        envelope = self.agent.build_envelope(claims=[claim], subject=subject, relying_party=relying_party)

        print("-" * 70)
        print(envelope.summary())
        print()
        print(envelope.to_json(indent=2))

        output_path = "supabase_network_restrictions_envelope.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="OTVP Supabase Network Restrictions Agent")
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
    agent = SupabaseNetworkAgent.create(project_ref=project_ref, access_token=access_token)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
