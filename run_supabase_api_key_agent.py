#!/usr/bin/env python3
"""
OTVP Supabase Agent: API Key Hygiene

Verifies API key management practices for the Supabase project:
whether the project uses the new publishable/secret key model,
legacy key status, key types and their exposure levels.

Maps to SOC 2 CC6.1 (Logical Access Security), CC6.6 (System Boundaries).

Usage:
    export SUPABASE_ACCESS_TOKEN=<personal-access-token>
    export SUPABASE_PROJECT_REF=<project-ref>
    python run_supabase_api_key_agent.py
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
from otvp_agent.agents.supabase.constants import DOMAIN_API_KEY_HYGIENE
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_api_key")


# ── Key Classification ─────────────────────────────────────────────

# Supabase key types by tag or name pattern
KEY_CLASSIFICATIONS = {
    "anon": {
        "role": "anon",
        "exposure": "public",
        "description": "Anonymous key — safe to embed in client-side code",
        "legacy": True,
    },
    "service_role": {
        "role": "service_role",
        "exposure": "secret",
        "description": "Service role key — bypasses RLS, must never be exposed client-side",
        "legacy": True,
    },
    "publishable": {
        "role": "publishable",
        "exposure": "public",
        "description": "Publishable key — new model replacement for anon key",
        "legacy": False,
    },
    "secret": {
        "role": "secret",
        "exposure": "secret",
        "description": "Secret key — new model replacement for service_role key",
        "legacy": False,
    },
}


def _classify_key(key: dict) -> dict:
    """Classify an API key by its name/tags to determine type and exposure."""
    name = key.get("name", "").lower()
    tags = key.get("tags", "")
    if isinstance(tags, str):
        tags = tags.lower()

    # Try to match by name or tags
    for key_type, info in KEY_CLASSIFICATIONS.items():
        if key_type in name or key_type in str(tags):
            return {
                "key_type": key_type,
                "role": info["role"],
                "exposure": info["exposure"],
                "description": info["description"],
                "is_legacy": info["legacy"],
            }

    # Unknown key type
    return {
        "key_type": "unknown",
        "role": "unknown",
        "exposure": "unknown",
        "description": f"Unrecognized key: {key.get('name', '?')}",
        "is_legacy": False,
    }


# ── Collector ──────────────────────────────────────────────────────


class APIKeyCollector(Collector):
    """Collects API key information from the Supabase Management API."""

    domain = DOMAIN_API_KEY_HYGIENE
    source_type = "management_api"
    provider = "supabase"

    def __init__(self, api: SupabaseManagementAPI | None = None) -> None:
        self.api: SupabaseManagementAPI | None = api

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        api = self.api
        if api is None:
            raise RuntimeError("APIKeyCollector requires a SupabaseManagementAPI.")

        project_ref = api.project_ref
        keys = api.get_api_keys()

        # Classify each key
        classified_keys: list[dict] = []
        for key in keys:
            classification = _classify_key(key)
            classified_keys.append({
                "name": key.get("name", "unknown"),
                "api_key_prefix": key.get("api_key", "")[:12] + "..." if key.get("api_key") else "",
                **classification,
            })

        # Analyze key inventory
        has_legacy_anon = any(k["key_type"] == "anon" for k in classified_keys)
        has_legacy_service = any(k["key_type"] == "service_role" for k in classified_keys)
        has_new_publishable = any(k["key_type"] == "publishable" for k in classified_keys)
        has_new_secret = any(k["key_type"] == "secret" for k in classified_keys)
        has_migrated = has_new_publishable or has_new_secret
        legacy_still_active = has_legacy_anon or has_legacy_service

        secret_keys = [k for k in classified_keys if k["exposure"] == "secret"]
        public_keys = [k for k in classified_keys if k["exposure"] == "public"]

        evidence_items: list[Evidence] = []

        # Evidence 1: Key inventory
        evidence_items.append(
            Evidence(
                evidence_type=EvidenceType.CONFIGURATION,
                domain=self.domain,
                source={
                    "provider": "supabase",
                    "service": "api_keys",
                    "resource_type": "key_inventory",
                    "resource_id": "api.keys",
                    "project_ref": project_ref,
                    "collection_method": "management_api",
                },
                observation={
                    "check": "key_inventory",
                    "total_keys": len(classified_keys),
                    "keys": classified_keys,
                    "public_key_count": len(public_keys),
                    "secret_key_count": len(secret_keys),
                    "passed": True,  # Informational
                    "severity": "none",
                    "detail": (
                        f"{len(classified_keys)} API key(s) found: "
                        f"{len(public_keys)} public, {len(secret_keys)} secret."
                    ),
                },
                tags={
                    "framework": "soc2",
                    "criteria": "CC6.1,CC6.6",
                    "agent": "supabase-api-key-hygiene",
                },
            )
        )

        # Evidence 2: Key model migration status
        if has_migrated and not legacy_still_active:
            migration_status = "migrated"
            migration_passed = True
            migration_severity = "none"
            migration_detail = (
                "Project has migrated to the new publishable/secret key model. "
                "Legacy anon/service_role keys are no longer active."
            )
        elif has_migrated and legacy_still_active:
            migration_status = "in_progress"
            migration_passed = False
            migration_severity = "medium"
            legacy_types = []
            if has_legacy_anon:
                legacy_types.append("anon")
            if has_legacy_service:
                legacy_types.append("service_role")
            migration_detail = (
                f"New key model is available but legacy keys ({', '.join(legacy_types)}) "
                "are still active. Consider revoking legacy keys after migration."
            )
        else:
            migration_status = "not_migrated"
            migration_passed = True  # Legacy model is still valid
            migration_severity = "none"
            migration_detail = (
                "Project uses the standard anon/service_role key model. "
                "New publishable/secret key model is not yet adopted."
            )

        evidence_items.append(
            Evidence(
                evidence_type=EvidenceType.CONFIGURATION,
                domain=self.domain,
                source={
                    "provider": "supabase",
                    "service": "api_keys",
                    "resource_type": "key_migration",
                    "resource_id": "api.key_model",
                    "project_ref": project_ref,
                    "collection_method": "management_api",
                },
                observation={
                    "check": "key_model_migration",
                    "migration_status": migration_status,
                    "has_legacy_anon": has_legacy_anon,
                    "has_legacy_service_role": has_legacy_service,
                    "has_new_publishable": has_new_publishable,
                    "has_new_secret": has_new_secret,
                    "passed": migration_passed,
                    "severity": migration_severity,
                    "detail": migration_detail,
                },
                tags={
                    "framework": "soc2",
                    "criteria": "CC6.1,CC6.6",
                    "agent": "supabase-api-key-hygiene",
                },
            )
        )

        # Evidence 3: Secret key exposure risk
        # Check that secret/service_role keys are properly classified
        secret_key_names = [k["name"] for k in secret_keys]
        if secret_keys:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.CONFIGURATION,
                    domain=self.domain,
                    source={
                        "provider": "supabase",
                        "service": "api_keys",
                        "resource_type": "secret_key_check",
                        "resource_id": "api.secret_keys",
                        "project_ref": project_ref,
                        "collection_method": "management_api",
                    },
                    observation={
                        "check": "secret_key_count",
                        "secret_keys": secret_key_names,
                        "count": len(secret_keys),
                        "passed": True,
                        "severity": "none",
                        "detail": (
                            f"{len(secret_keys)} secret key(s) exist: "
                            f"{', '.join(secret_key_names)}. "
                            "Ensure these are never exposed in client-side code, "
                            "public repos, or browser-accessible bundles."
                        ),
                    },
                    tags={
                        "framework": "soc2",
                        "criteria": "CC6.1,CC6.6",
                        "agent": "supabase-api-key-hygiene",
                    },
                )
            )

        return evidence_items


# ── Evaluator ──────────────────────────────────────────────────────


class APIKeyEvaluator(SupabaseEvaluator):
    """Evaluates API key hygiene for a Supabase project."""

    domain = DOMAIN_API_KEY_HYGIENE
    assertion = (
        "API keys are properly managed with appropriate key model, "
        "no unnecessary legacy keys, and secret keys protected"
    )

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(
                result=ClaimResult.INDETERMINATE,
                confidence=0.0,
                assessment="Could not retrieve API key information.",
                evidence_ids=[],
            )

        passed_checks: list[str] = []
        failed_checks: list[dict] = []

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            check = obs.get("check", "?")
            passed = obs.get("passed", False)
            severity = obs.get("severity", "none")
            detail = obs.get("detail", "")

            if passed:
                passed_checks.append(check)
            else:
                failed_checks.append({
                    "check": check,
                    "severity": severity,
                    "detail": detail,
                })

        total = len(evidence_items)
        pass_count = len(passed_checks)
        all_evidence_ids = [e.evidence_id for e in evidence_items]

        if pass_count == total:
            return EvaluationResult(
                result=ClaimResult.SATISFIED,
                confidence=1.0,
                assessment=(
                    f"All {total} API key check(s) pass. "
                    "Key management follows best practices."
                ),
                evidence_ids=all_evidence_ids,
            )

        if pass_count == 0:
            return EvaluationResult(
                result=ClaimResult.NOT_SATISFIED,
                confidence=1.0,
                assessment=(
                    f"All {total} API key check(s) have issues."
                ),
                caveats=[
                    f"{f['check']} [{f['severity']}]: {f['detail']}"
                    for f in failed_checks[:10]
                ],
                recommendations=_recommendations(failed_checks),
                evidence_ids=all_evidence_ids,
            )

        confidence = round(pass_count / total, 3)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        failed_sorted = sorted(
            failed_checks,
            key=lambda f: severity_order.get(f["severity"], 4),
        )

        return EvaluationResult(
            result=ClaimResult.PARTIAL,
            confidence=confidence,
            assessment=(
                f"{pass_count}/{total} API key check(s) pass. "
                f"{len(failed_checks)} issue(s) found."
            ),
            caveats=[
                f"{f['check']} [{f['severity']}]: {f['detail']}"
                for f in failed_sorted[:10]
            ],
            recommendations=_recommendations(failed_sorted),
            evidence_ids=all_evidence_ids,
        )


def _recommendations(failed: list[dict]) -> list[str]:
    """Generate recommendations from failed checks."""
    recs = []
    for f in failed[:5]:
        check = f["check"]
        if check == "key_model_migration":
            recs.append(
                "Complete migration to the new publishable/secret key model. "
                "Revoke legacy anon/service_role keys once all clients are updated."
            )
        elif check == "secret_key_count":
            recs.append(
                "Audit secret key usage: ensure service_role/secret keys are only "
                "used server-side and never exposed in client bundles or public repos."
            )
        else:
            recs.append(f"Review API key issue: {f['detail']}")
    return recs


# ── Composite Agent ────────────────────────────────────────────────


class SupabaseAPIKeyAgent:
    """Orchestrates API key hygiene verification for a Supabase project."""

    def __init__(self, agent: Agent, api: SupabaseManagementAPI) -> None:
        self.agent = agent
        self.api = api
        self.collector = APIKeyCollector()
        self.evaluator = APIKeyEvaluator()

    @classmethod
    def create(
        cls,
        project_ref: str | None = None,
        access_token: str | None = None,
    ) -> SupabaseAPIKeyAgent:
        keys = KeyPair.generate()
        config = AgentConfig(
            agent_id="supabase-api-key-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0",
            key_pair=keys,
            domains=[Domain.API_KEY_HYGIENE],
        )
        agent = Agent(config)
        api = SupabaseManagementAPI(
            access_token=access_token,
            project_ref=project_ref,
        )
        return cls(agent=agent, api=api)

    async def run(
        self,
        subject: str = "killswitch-advisory",
        relying_party: str | None = None,
    ) -> None:
        project_ref = self.api.project_ref or "(unknown)"

        print("=" * 70)
        print("  OTVP Supabase Agent: API Key Hygiene")
        print(f"  Project: {project_ref}")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        # 1. Collect
        self.collector.api = self.api
        ctx = CollectionContext(
            environment="production",
            custom={"project_ref": project_ref},
        )
        evidence = await self.collector.collect(ctx)

        passed = sum(
            1 for e in evidence
            if isinstance(e.observation, dict) and e.observation.get("passed")
        )
        print(f"  Collected {len(evidence)} API key evidence items")
        print(f"    Passed: {passed}")
        print(f"    Failed: {len(evidence) - passed}")
        print()

        # 2. Sign and store
        signed_refs = []
        for ev in evidence:
            signed = self.agent.sign_evidence(ev)
            signed_refs.append(signed.evidence_id)

        # 3. Evaluate
        result = await self.evaluator.evaluate(evidence)
        print(f"  Evaluation: {result.result.value}")
        print(f"  Confidence: {result.confidence:.0%}")
        print(f"  Assessment: {result.assessment}")
        if result.caveats:
            for c in result.caveats:
                print(f"  ! Caveat: {c}")
        if result.recommendations:
            for r in result.recommendations:
                print(f"  > Recommendation: {r}")
        print()

        # 4. Create signed claim
        claim = self.agent.create_claim(
            domain=DOMAIN_API_KEY_HYGIENE,
            assertion=self.evaluator.assertion,
            result=result.result,
            confidence=result.confidence,
            evidence_refs=signed_refs,
            opinion=result.assessment,
            caveats=result.caveats,
            recommendations=result.recommendations,
            scope=ClaimScope(
                environment="production",
                services=["Supabase API Keys"],
                regions=[project_ref],
            ),
        )

        # 5. Build envelope
        envelope = self.agent.build_envelope(
            claims=[claim],
            subject=subject,
            relying_party=relying_party,
        )

        # 6. Summary
        print("-" * 70)
        print(envelope.summary())
        print()

        # 7. Verification
        print("-" * 70)
        print("Verification:")
        print(f"  Envelope signature valid: {self.agent.verify_envelope(envelope)}")
        for c in envelope.claims:
            print(f"  Claim [{c.claim_id}] signature valid: {self.agent.verify_claim(c)}")
        print(f"  Evidence store size: {self.agent.evidence_store.size}")
        print(f"  Merkle root: {self.agent.evidence_store.root_hash}")
        print()

        store = self.agent.evidence_store
        for i in range(min(3, store.size)):
            proof = store.get_proof(i)
            print(f"  Evidence [{i}] Merkle proof valid: {proof.verify()}")
        print()

        # 8. Full JSON
        print("-" * 70)
        print("Full Trust Envelope (JSON):")
        print("-" * 70)
        print(envelope.to_json(indent=2))

        # 9. Save
        output_path = "supabase_api_key_hygiene_envelope.json"
        with open(output_path, "w") as f:
            f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


# ── CLI ────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OTVP Supabase API Key Hygiene Agent",
    )
    parser.add_argument(
        "--subject",
        default="killswitch-advisory",
        help="Subject organization name (default: killswitch-advisory)",
    )
    parser.add_argument(
        "--relying-party",
        default=None,
        help="Relying party organization name",
    )
    parser.add_argument(
        "--project-ref",
        default=None,
        help="Supabase project reference (overrides SUPABASE_PROJECT_REF env var)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    access_token = os.environ.get("SUPABASE_ACCESS_TOKEN", "")
    project_ref = args.project_ref or os.environ.get("SUPABASE_PROJECT_REF", "")
    if not access_token:
        print("ERROR: SUPABASE_ACCESS_TOKEN environment variable is required.", file=sys.stderr)
        print("  Create one at: https://supabase.com/dashboard/account/tokens", file=sys.stderr)
        sys.exit(1)
    if not project_ref:
        print("ERROR: SUPABASE_PROJECT_REF is required (env var or --project-ref).", file=sys.stderr)
        sys.exit(1)

    agent = SupabaseAPIKeyAgent.create(
        project_ref=project_ref,
        access_token=access_token,
    )
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))


if __name__ == "__main__":
    main()
