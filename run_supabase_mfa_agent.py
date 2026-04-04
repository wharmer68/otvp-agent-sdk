#!/usr/bin/env python3
"""
OTVP Supabase Agent: MFA Enrollment

Verifies MFA configuration at the project level and measures enrollment
adoption across active users.  Checks whether TOTP and phone MFA are
enabled, factor limits, and what percentage of users have enrolled at
least one MFA factor.

Maps to SOC 2 CC6.1 (Logical Access Security), CC6.2 (User Lifecycle).

Usage:
    export SUPABASE_ACCESS_TOKEN=<personal-access-token>
    export SUPABASE_PROJECT_REF=<project-ref>
    export SUPABASE_DB_HOST=aws-0-us-east-1.pooler.supabase.com
    export SUPABASE_DB_PORT=6543
    export SUPABASE_DB_USER=postgres.<project-ref>
    export SUPABASE_DB_PASSWORD=<your-db-password>
    python run_supabase_mfa_agent.py
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
from otvp_agent.agents.supabase.connection import SupabaseConnection
from otvp_agent.agents.supabase.management import SupabaseManagementAPI
from otvp_agent.agents.supabase.constants import DOMAIN_MFA_ENROLLMENT
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_mfa")


# ── SQL Queries (auth schema) ─────────────────────────────────────

# Count total confirmed users (active accounts)
SQL_TOTAL_USERS = """
SELECT count(*) AS total
FROM auth.users
WHERE confirmed_at IS NOT NULL;
"""

# Count users with at least one verified MFA factor
SQL_MFA_ENROLLED = """
SELECT count(DISTINCT user_id) AS enrolled
FROM auth.mfa_factors
WHERE status = 'verified';
"""

# Breakdown of MFA factor types
SQL_FACTOR_TYPES = """
SELECT
    factor_type,
    count(*) AS factor_count,
    count(DISTINCT user_id) AS user_count
FROM auth.mfa_factors
WHERE status = 'verified'
GROUP BY factor_type
ORDER BY factor_type;
"""

# Users with unverified (pending) factors — may indicate enrollment friction
SQL_PENDING_FACTORS = """
SELECT count(DISTINCT user_id) AS pending
FROM auth.mfa_factors
WHERE status = 'unverified';
"""


# ── Collector ──────────────────────────────────────────────────────


class MFAEnrollmentCollector(Collector):
    """Collects MFA config from Management API and enrollment stats from DB."""

    domain = DOMAIN_MFA_ENROLLMENT
    source_type = "hybrid"
    provider = "supabase"

    def __init__(
        self,
        api: SupabaseManagementAPI | None = None,
        connection: SupabaseConnection | None = None,
    ) -> None:
        self.api: SupabaseManagementAPI | None = api
        self.connection: SupabaseConnection | None = connection

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        evidence_items: list[Evidence] = []
        project_ref = ""

        # ── Part 1: Project-level MFA config from Management API ───
        if self.api:
            project_ref = self.api.project_ref
            auth_config = self.api.get_auth_config()

            totp_enabled = auth_config.get("MFA_TOTP_ENROLL_ENABLED", False)
            phone_enabled = auth_config.get("MFA_PHONE_ENROLL_ENABLED", False)
            max_factors = auth_config.get("MFA_MAX_ENROLLED_FACTORS", 10)
            # Some Supabase versions use different keys
            if not totp_enabled:
                totp_enabled = auth_config.get("MFA_ENABLED", False)

            any_mfa_enabled = totp_enabled or phone_enabled

            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.CONFIGURATION,
                    domain=self.domain,
                    source={
                        "provider": "supabase",
                        "service": "auth",
                        "resource_type": "mfa_config",
                        "resource_id": "auth.mfa_config",
                        "project_ref": project_ref,
                        "collection_method": "management_api",
                    },
                    observation={
                        "check": "mfa_project_config",
                        "totp_enabled": totp_enabled,
                        "phone_enabled": phone_enabled,
                        "max_enrolled_factors": max_factors,
                        "any_mfa_enabled": any_mfa_enabled,
                        "passed": any_mfa_enabled,
                        "severity": "high" if not any_mfa_enabled else "none",
                        "detail": (
                            "MFA is not enabled at the project level. "
                            "Neither TOTP nor phone MFA enrollment is active."
                            if not any_mfa_enabled else
                            f"MFA enabled — TOTP: {totp_enabled}, Phone: {phone_enabled}, "
                            f"Max factors per user: {max_factors}."
                        ),
                    },
                    tags={
                        "framework": "soc2",
                        "criteria": "CC6.1,CC6.2",
                        "agent": "supabase-mfa-enrollment",
                    },
                )
            )

        # ── Part 2: Enrollment stats from database ─────────────────
        if self.connection:
            if not project_ref:
                project_ref = self.connection.project_ref

            try:
                total_rows = self.connection.execute(SQL_TOTAL_USERS)
                total_users = total_rows[0]["total"] if total_rows else 0

                enrolled_rows = self.connection.execute(SQL_MFA_ENROLLED)
                enrolled_users = enrolled_rows[0]["enrolled"] if enrolled_rows else 0

                factor_rows = self.connection.execute(SQL_FACTOR_TYPES)
                factor_breakdown = [
                    {
                        "factor_type": r["factor_type"],
                        "factor_count": r["factor_count"],
                        "user_count": r["user_count"],
                    }
                    for r in factor_rows
                ]

                pending_rows = self.connection.execute(SQL_PENDING_FACTORS)
                pending_users = pending_rows[0]["pending"] if pending_rows else 0

                enrollment_rate = (
                    round(enrolled_users / total_users, 3)
                    if total_users > 0 else 0.0
                )

                # Determine severity based on enrollment rate
                if total_users == 0:
                    severity = "none"
                    passed = True
                elif enrollment_rate >= 0.8:
                    severity = "none"
                    passed = True
                elif enrollment_rate >= 0.5:
                    severity = "medium"
                    passed = False
                else:
                    severity = "high"
                    passed = False

                evidence_items.append(
                    Evidence(
                        evidence_type=EvidenceType.CONFIGURATION,
                        domain=self.domain,
                        source={
                            "provider": "supabase",
                            "service": "auth",
                            "resource_type": "mfa_enrollment",
                            "resource_id": "auth.mfa_factors",
                            "project_ref": project_ref,
                            "collection_method": "sql_query",
                        },
                        observation={
                            "check": "mfa_enrollment_rate",
                            "total_users": total_users,
                            "enrolled_users": enrolled_users,
                            "enrollment_rate": enrollment_rate,
                            "pending_users": pending_users,
                            "factor_breakdown": factor_breakdown,
                            "passed": passed,
                            "severity": severity,
                            "detail": (
                                f"{enrolled_users}/{total_users} confirmed user(s) "
                                f"({enrollment_rate:.0%}) have MFA enrolled. "
                                f"{pending_users} user(s) have pending (unverified) factors."
                                if total_users > 0 else
                                "No confirmed users found in the project."
                            ),
                        },
                        tags={
                            "framework": "soc2",
                            "criteria": "CC6.1,CC6.2",
                            "agent": "supabase-mfa-enrollment",
                        },
                    )
                )
            except Exception as exc:
                logger.warning("Could not query auth.mfa_factors: %s", exc)
                evidence_items.append(
                    Evidence(
                        evidence_type=EvidenceType.CONFIGURATION,
                        domain=self.domain,
                        source={
                            "provider": "supabase",
                            "service": "auth",
                            "resource_type": "mfa_enrollment",
                            "resource_id": "auth.mfa_factors",
                            "project_ref": project_ref,
                            "collection_method": "sql_query",
                        },
                        observation={
                            "check": "mfa_enrollment_rate",
                            "error": str(exc),
                            "passed": False,
                            "severity": "medium",
                            "detail": (
                                f"Unable to query MFA enrollment stats: {exc}. "
                                "The database user may not have access to the auth schema."
                            ),
                        },
                        tags={
                            "framework": "soc2",
                            "criteria": "CC6.1,CC6.2",
                            "agent": "supabase-mfa-enrollment",
                        },
                    )
                )

        return evidence_items


# ── Evaluator ──────────────────────────────────────────────────────


class MFAEnrollmentEvaluator(SupabaseEvaluator):
    """Evaluates MFA configuration and enrollment adoption."""

    domain = DOMAIN_MFA_ENROLLMENT
    assertion = (
        "MFA is enabled at the project level and actively enrolled "
        "by users"
    )

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(
                result=ClaimResult.INDETERMINATE,
                confidence=0.0,
                assessment="Could not collect MFA configuration or enrollment data.",
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
                    f"All {total} MFA check(s) pass. MFA is enabled and "
                    "enrollment adoption meets thresholds."
                ),
                evidence_ids=all_evidence_ids,
            )

        if pass_count == 0:
            return EvaluationResult(
                result=ClaimResult.NOT_SATISFIED,
                confidence=1.0,
                assessment=(
                    f"All {total} MFA check(s) have issues. "
                    + "; ".join(f["detail"] for f in failed_checks[:3])
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
                f"{pass_count}/{total} MFA check(s) pass. "
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
        if check == "mfa_project_config":
            recs.append(
                "Enable MFA in Auth settings: turn on TOTP enrollment at minimum. "
                "Go to Authentication > Multi-Factor Authentication in the dashboard."
            )
        elif check == "mfa_enrollment_rate":
            recs.append(
                "Encourage MFA enrollment across your user base. Consider: "
                "(1) prompting users to enroll on next login, "
                "(2) requiring MFA for sensitive operations, "
                "(3) offering enrollment incentives."
            )
        else:
            recs.append(f"Review MFA setting: {f['detail']}")
    return recs


# ── Composite Agent ────────────────────────────────────────────────


class SupabaseMFAAgent:
    """Orchestrates MFA enrollment verification for a Supabase project."""

    def __init__(
        self,
        agent: Agent,
        api: SupabaseManagementAPI | None,
        connection: SupabaseConnection | None,
    ) -> None:
        self.agent = agent
        self.api = api
        self.connection = connection
        self.collector = MFAEnrollmentCollector()
        self.evaluator = MFAEnrollmentEvaluator()

    @classmethod
    def create(
        cls,
        project_ref: str | None = None,
        access_token: str | None = None,
        db_host: str | None = None,
        db_password: str | None = None,
    ) -> SupabaseMFAAgent:
        keys = KeyPair.generate()
        config = AgentConfig(
            agent_id="supabase-mfa-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0",
            key_pair=keys,
            domains=[Domain.MFA_ENROLLMENT],
        )
        agent = Agent(config)

        # Management API (for project-level config)
        api = None
        token = access_token or os.environ.get("SUPABASE_ACCESS_TOKEN", "")
        ref = project_ref or os.environ.get("SUPABASE_PROJECT_REF", "")
        if token and ref:
            api = SupabaseManagementAPI(access_token=token, project_ref=ref)

        # Database connection (for enrollment stats)
        connection = None
        host = db_host or os.environ.get("SUPABASE_DB_HOST", "")
        password = db_password or os.environ.get("SUPABASE_DB_PASSWORD", "")
        if host and password:
            connection = SupabaseConnection(
                host=host,
                password=password,
                project_ref=ref,
            )

        return cls(agent=agent, api=api, connection=connection)

    async def run(
        self,
        subject: str = "killswitch-advisory",
        relying_party: str | None = None,
    ) -> None:
        project_ref = ""
        if self.api:
            project_ref = self.api.project_ref
        elif self.connection:
            project_ref = self.connection.project_ref
        project_ref = project_ref or "(unknown)"

        print("=" * 70)
        print("  OTVP Supabase Agent: MFA Enrollment")
        print(f"  Project: {project_ref}")
        print(f"  Subject: {subject}")
        print(f"  Data sources: ", end="")
        sources = []
        if self.api:
            sources.append("Management API")
        if self.connection:
            sources.append("Database")
        print(", ".join(sources) if sources else "none")
        print("=" * 70)
        print()

        # 1. Collect — open DB connection if available
        self.collector.api = self.api
        if self.connection:
            with self.connection as conn:
                self.collector.connection = conn
                ctx = CollectionContext(
                    environment="production",
                    custom={"project_ref": project_ref},
                )
                evidence = await self.collector.collect(ctx)
        else:
            self.collector.connection = None
            ctx = CollectionContext(
                environment="production",
                custom={"project_ref": project_ref},
            )
            evidence = await self.collector.collect(ctx)

        passed = sum(
            1 for e in evidence
            if isinstance(e.observation, dict) and e.observation.get("passed")
        )
        print(f"  Collected {len(evidence)} MFA evidence items")
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
            domain=DOMAIN_MFA_ENROLLMENT,
            assertion=self.evaluator.assertion,
            result=result.result,
            confidence=result.confidence,
            evidence_refs=signed_refs,
            opinion=result.assessment,
            caveats=result.caveats,
            recommendations=result.recommendations,
            scope=ClaimScope(
                environment="production",
                services=["Supabase Auth"],
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
        output_path = "supabase_mfa_enrollment_envelope.json"
        with open(output_path, "w") as f:
            f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


# ── CLI ────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OTVP Supabase MFA Enrollment Agent",
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

    # Check that at least one data source is available
    access_token = os.environ.get("SUPABASE_ACCESS_TOKEN", "")
    db_host = os.environ.get("SUPABASE_DB_HOST", "")
    project_ref = args.project_ref or os.environ.get("SUPABASE_PROJECT_REF", "")

    if not access_token and not db_host:
        print(
            "ERROR: At least one data source is required.\n"
            "  For project config: set SUPABASE_ACCESS_TOKEN and SUPABASE_PROJECT_REF\n"
            "  For enrollment stats: set SUPABASE_DB_HOST and SUPABASE_DB_PASSWORD\n"
            "  Both can be set for the most complete assessment.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not project_ref:
        print("ERROR: SUPABASE_PROJECT_REF is required (env var or --project-ref).", file=sys.stderr)
        sys.exit(1)

    agent = SupabaseMFAAgent.create(project_ref=project_ref)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))


if __name__ == "__main__":
    main()
