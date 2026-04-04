#!/usr/bin/env python3
"""
OTVP Supabase Agent: Auth Configuration

Verifies Supabase Auth settings against security best practices:
email confirmation, password policy, anonymous sign-ups, OAuth providers,
session timeouts, and rate limiting.

Maps to SOC 2 CC6.1 (Logical Access Security), CC6.2 (User Lifecycle).

Usage:
    export SUPABASE_ACCESS_TOKEN=<personal-access-token>
    export SUPABASE_PROJECT_REF=<project-ref>
    python run_supabase_auth_config_agent.py
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
from otvp_agent.agents.supabase.constants import DOMAIN_AUTH_CONFIG
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.supabase_auth_config")


# ── Configuration Checks ──────────────────────────────────────────

# Each check inspects one aspect of auth config and returns a finding dict.
# Keys in the auth config response are documented at:
# https://supabase.com/docs/reference/api/get-project-auth-config

RECOMMENDED_MIN_PASSWORD_LENGTH = 8


def _check_email_confirmation(config: dict) -> dict:
    """Check that email confirmation is required, not optional."""
    # MAILER_AUTOCONFIRM = true means users skip email confirmation
    autoconfirm = config.get("MAILER_AUTOCONFIRM", False)
    return {
        "check": "email_confirmation",
        "setting": "MAILER_AUTOCONFIRM",
        "value": autoconfirm,
        "expected": False,
        "passed": not autoconfirm,
        "severity": "high" if autoconfirm else "none",
        "detail": (
            "Email auto-confirm is ENABLED — users can sign up without "
            "verifying their email address. This weakens account verification."
            if autoconfirm else
            "Email confirmation is required before account activation."
        ),
    }


def _check_password_length(config: dict) -> dict:
    """Check that minimum password length meets policy."""
    min_length = config.get("PASSWORD_MIN_LENGTH", 6)
    passed = min_length >= RECOMMENDED_MIN_PASSWORD_LENGTH
    return {
        "check": "password_min_length",
        "setting": "PASSWORD_MIN_LENGTH",
        "value": min_length,
        "expected": f">= {RECOMMENDED_MIN_PASSWORD_LENGTH}",
        "passed": passed,
        "severity": "medium" if not passed else "none",
        "detail": (
            f"Minimum password length is {min_length} (recommended: "
            f"{RECOMMENDED_MIN_PASSWORD_LENGTH}+). Short passwords are "
            "vulnerable to brute-force attacks."
            if not passed else
            f"Minimum password length is {min_length}, meets recommendation."
        ),
    }


def _check_anonymous_signups(config: dict) -> dict:
    """Check if anonymous sign-ups are disabled."""
    # EXTERNAL_ANONYMOUS_USERS_ENABLED = true allows anonymous auth
    anon_enabled = config.get("EXTERNAL_ANONYMOUS_USERS_ENABLED", False)
    return {
        "check": "anonymous_signups",
        "setting": "EXTERNAL_ANONYMOUS_USERS_ENABLED",
        "value": anon_enabled,
        "expected": False,
        "passed": not anon_enabled,
        "severity": "medium" if anon_enabled else "none",
        "detail": (
            "Anonymous sign-ups are ENABLED — users can create sessions "
            "without providing credentials. Ensure RLS policies account for "
            "the anon role if this is intentional."
            if anon_enabled else
            "Anonymous sign-ups are disabled."
        ),
    }


def _check_oauth_providers(config: dict) -> dict:
    """Catalog which OAuth/social providers are enabled.

    This is informational — having providers enabled isn't inherently bad,
    but the agent should surface which authentication methods are active.
    """
    providers_checked = [
        ("EXTERNAL_GOOGLE_ENABLED", "Google"),
        ("EXTERNAL_GITHUB_ENABLED", "GitHub"),
        ("EXTERNAL_APPLE_ENABLED", "Apple"),
        ("EXTERNAL_AZURE_ENABLED", "Azure"),
        ("EXTERNAL_FACEBOOK_ENABLED", "Facebook"),
        ("EXTERNAL_TWITTER_ENABLED", "Twitter"),
        ("EXTERNAL_DISCORD_ENABLED", "Discord"),
        ("EXTERNAL_SLACK_ENABLED", "Slack"),
        ("EXTERNAL_SPOTIFY_ENABLED", "Spotify"),
        ("EXTERNAL_LINKEDIN_OIDC_ENABLED", "LinkedIn"),
        ("EXTERNAL_BITBUCKET_ENABLED", "Bitbucket"),
        ("EXTERNAL_GITLAB_ENABLED", "GitLab"),
        ("EXTERNAL_KEYCLOAK_ENABLED", "Keycloak"),
        ("EXTERNAL_NOTION_ENABLED", "Notion"),
        ("EXTERNAL_TWITCH_ENABLED", "Twitch"),
        ("EXTERNAL_WORKOS_ENABLED", "WorkOS"),
        ("EXTERNAL_ZOOM_ENABLED", "Zoom"),
        ("EXTERNAL_FLY_IO_ENABLED", "Fly.io"),
        ("EXTERNAL_KAKAO_ENABLED", "Kakao"),
    ]
    enabled = [name for key, name in providers_checked if config.get(key, False)]
    # Having providers is fine — this is informational, always passes
    return {
        "check": "oauth_providers",
        "setting": "EXTERNAL_*_ENABLED",
        "value": enabled,
        "expected": "informational",
        "passed": True,
        "severity": "none",
        "detail": (
            f"{len(enabled)} OAuth provider(s) enabled: {', '.join(enabled)}."
            if enabled else
            "No OAuth/social providers enabled. Only email/password auth is active."
        ),
    }


def _check_session_timeouts(config: dict) -> dict:
    """Check session/JWT expiry configuration."""
    # JWT_EXP is the JWT expiry in seconds (default 3600)
    jwt_exp = config.get("JWT_EXP", 3600)
    # REFRESH_TOKEN_ROTATION_ENABLED should be true for security
    refresh_rotation = config.get("REFRESH_TOKEN_ROTATION_ENABLED", False)

    issues = []
    if jwt_exp > 3600:
        issues.append(
            f"JWT expiry is {jwt_exp}s ({jwt_exp // 3600}h) — "
            "consider reducing to 3600s (1h) or less"
        )
    if not refresh_rotation:
        issues.append("Refresh token rotation is disabled — enables token replay attacks")

    passed = len(issues) == 0
    severity = "none"
    if not refresh_rotation:
        severity = "high"
    elif jwt_exp > 3600:
        severity = "medium"

    return {
        "check": "session_timeouts",
        "setting": "JWT_EXP, REFRESH_TOKEN_ROTATION_ENABLED",
        "value": {"jwt_exp_seconds": jwt_exp, "refresh_rotation": refresh_rotation},
        "expected": {"jwt_exp_seconds": "<= 3600", "refresh_rotation": True},
        "passed": passed,
        "severity": severity,
        "detail": (
            "; ".join(issues) if issues else
            f"JWT expiry is {jwt_exp}s with refresh token rotation enabled."
        ),
    }


def _check_rate_limiting(config: dict) -> dict:
    """Check if rate limiting is configured on auth endpoints."""
    # RATE_LIMIT_EMAIL_SENT is emails per hour (default varies)
    email_rate = config.get("RATE_LIMIT_EMAIL_SENT", None)
    # RATE_LIMIT_SMS_SENT is SMS per hour
    sms_rate = config.get("RATE_LIMIT_SMS_SENT", None)
    # SECURITY_CAPTCHA_ENABLED
    captcha = config.get("SECURITY_CAPTCHA_ENABLED", False)

    issues = []
    if not captcha:
        issues.append("CAPTCHA is not enabled on auth endpoints")

    passed = len(issues) == 0
    return {
        "check": "rate_limiting",
        "setting": "RATE_LIMIT_*, SECURITY_CAPTCHA_ENABLED",
        "value": {
            "email_rate_limit": email_rate,
            "sms_rate_limit": sms_rate,
            "captcha_enabled": captcha,
        },
        "expected": {"captcha_enabled": True},
        "passed": passed,
        "severity": "low" if not passed else "none",
        "detail": (
            "; ".join(issues) if issues else
            "CAPTCHA is enabled on auth endpoints."
        ),
    }


ALL_CHECKS = [
    _check_email_confirmation,
    _check_password_length,
    _check_anonymous_signups,
    _check_oauth_providers,
    _check_session_timeouts,
    _check_rate_limiting,
]


# ── Collector ──────────────────────────────────────────────────────


class AuthConfigCollector(Collector):
    """Collects auth configuration from the Supabase Management API."""

    domain = DOMAIN_AUTH_CONFIG
    source_type = "management_api"
    provider = "supabase"

    def __init__(self, api: SupabaseManagementAPI | None = None) -> None:
        self.api: SupabaseManagementAPI | None = api

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        api = self.api
        if api is None:
            raise RuntimeError("AuthConfigCollector requires a SupabaseManagementAPI.")

        # Fetch auth config from Management API
        auth_config = api.get_auth_config()
        project_ref = api.project_ref

        # Run each check against the config
        check_results = []
        for check_fn in ALL_CHECKS:
            check_results.append(check_fn(auth_config))

        # Produce one Evidence item per check
        evidence_items: list[Evidence] = []
        for result in check_results:
            evidence_items.append(
                Evidence(
                    evidence_type=EvidenceType.CONFIGURATION,
                    domain=self.domain,
                    source={
                        "provider": "supabase",
                        "service": "auth",
                        "resource_type": "auth_config",
                        "resource_id": f"auth.{result['check']}",
                        "project_ref": project_ref,
                        "collection_method": "management_api",
                    },
                    observation={
                        "check": result["check"],
                        "setting": result["setting"],
                        "value": result["value"],
                        "expected": result["expected"],
                        "passed": result["passed"],
                        "severity": result["severity"],
                        "detail": result["detail"],
                    },
                    tags={
                        "framework": "soc2",
                        "criteria": "CC6.1,CC6.2",
                        "agent": "supabase-auth-configuration",
                    },
                )
            )

        return evidence_items


# ── Evaluator ──────────────────────────────────────────────────────


class AuthConfigEvaluator(SupabaseEvaluator):
    """Evaluates auth configuration against security best practices."""

    domain = DOMAIN_AUTH_CONFIG
    assertion = (
        "Supabase Auth is configured following security best practices "
        "for email verification, password policy, session management, and rate limiting"
    )

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(
                result=ClaimResult.INDETERMINATE,
                confidence=0.0,
                assessment="Could not retrieve auth configuration to evaluate.",
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
                    f"All {total} auth configuration checks pass. "
                    "Auth settings follow security best practices."
                ),
                evidence_ids=all_evidence_ids,
            )

        if pass_count == 0:
            return EvaluationResult(
                result=ClaimResult.NOT_SATISFIED,
                confidence=1.0,
                assessment=(
                    f"All {total} auth configuration checks have issues."
                ),
                caveats=[
                    f"{f['check']}: {f['detail']}" for f in failed_checks[:10]
                ],
                recommendations=_recommendations(failed_checks),
                evidence_ids=all_evidence_ids,
            )

        # Partial
        confidence = round(pass_count / total, 3)

        # Sort failed checks by severity for caveats
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        failed_sorted = sorted(
            failed_checks,
            key=lambda f: severity_order.get(f["severity"], 4),
        )

        return EvaluationResult(
            result=ClaimResult.PARTIAL,
            confidence=confidence,
            assessment=(
                f"{pass_count}/{total} auth configuration checks pass. "
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
        if check == "email_confirmation":
            recs.append(
                "Disable MAILER_AUTOCONFIRM in Auth settings to require "
                "email verification before account activation."
            )
        elif check == "password_min_length":
            recs.append(
                f"Increase PASSWORD_MIN_LENGTH to at least "
                f"{RECOMMENDED_MIN_PASSWORD_LENGTH} in Auth settings."
            )
        elif check == "anonymous_signups":
            recs.append(
                "Disable anonymous sign-ups unless explicitly needed. "
                "If enabled, ensure all RLS policies properly handle the anon role."
            )
        elif check == "session_timeouts":
            recs.append(
                "Enable refresh token rotation and consider reducing JWT expiry "
                "to 3600s (1 hour) or less."
            )
        elif check == "rate_limiting":
            recs.append(
                "Enable CAPTCHA on auth endpoints to protect against "
                "automated credential stuffing."
            )
        else:
            recs.append(f"Review auth setting: {f['detail']}")
    return recs


# ── Composite Agent ────────────────────────────────────────────────


class SupabaseAuthConfigAgent:
    """Orchestrates auth configuration verification for a Supabase project."""

    def __init__(self, agent: Agent, api: SupabaseManagementAPI) -> None:
        self.agent = agent
        self.api = api
        self.collector = AuthConfigCollector()
        self.evaluator = AuthConfigEvaluator()

    @classmethod
    def create(
        cls,
        project_ref: str | None = None,
        access_token: str | None = None,
    ) -> SupabaseAuthConfigAgent:
        keys = KeyPair.generate()
        config = AgentConfig(
            agent_id="supabase-auth-config-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory",
            version="1.0.0",
            key_pair=keys,
            domains=[Domain.AUTH_CONFIGURATION],
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
        print("  OTVP Supabase Agent: Auth Configuration")
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
        failed = len(evidence) - passed
        print(f"  Collected {len(evidence)} auth configuration checks")
        print(f"    Passed: {passed}")
        print(f"    Failed: {failed}")
        print()

        # 2. Sign and store evidence
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
            domain=DOMAIN_AUTH_CONFIG,
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
        output_path = "supabase_auth_config_envelope.json"
        with open(output_path, "w") as f:
            f.write(envelope.to_json(indent=2))
        print(f"\n  Envelope saved to: {output_path}")


# ── CLI ────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OTVP Supabase Auth Configuration Agent",
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

    # Validate required env vars
    access_token = os.environ.get("SUPABASE_ACCESS_TOKEN", "")
    project_ref = args.project_ref or os.environ.get("SUPABASE_PROJECT_REF", "")
    if not access_token:
        print("ERROR: SUPABASE_ACCESS_TOKEN environment variable is required.", file=sys.stderr)
        print("  Create one at: https://supabase.com/dashboard/account/tokens", file=sys.stderr)
        sys.exit(1)
    if not project_ref:
        print("ERROR: SUPABASE_PROJECT_REF is required (env var or --project-ref).", file=sys.stderr)
        sys.exit(1)

    agent = SupabaseAuthConfigAgent.create(
        project_ref=project_ref,
        access_token=access_token,
    )
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))


if __name__ == "__main__":
    main()
