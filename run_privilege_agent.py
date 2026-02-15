#!/usr/bin/env python3
"""
OTVP Reference Agent: Least Privilege

Analyzes IAM policies for overprivileged access, admin sprawl, and inline policies.
Maps to SOC 2 CC6.3 | ISO 27001 A.9.2.3 | NIST CSF PR.AC-4

Usage:
    export AWS_PROFILE=otvp-test
    python run_privilege_agent.py
"""
from __future__ import annotations

import asyncio
import argparse
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import boto3
from botocore.exceptions import ClientError
from otvp_agent import Agent, AgentConfig, KeyPair, Evidence
from otvp_agent.agents import Collector, CollectionContext, EvaluationResult
from otvp_agent.claims import ClaimResult, ClaimScope

logger = logging.getLogger("otvp.agent.aws_privilege")

ADMIN_POLICIES = {"arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/IAMFullAccess",
                  "arn:aws:iam::aws:policy/PowerUserAccess"}


class LeastPrivilegeCollector(Collector):
    domain = "identity_and_access.authorization.least_privilege"
    source_type = "cloud_api"
    provider = "aws"

    async def collect(self, context: CollectionContext) -> list[Evidence]:
        iam = boto3.client("iam")
        evidence_items = []

        # Check users
        try:
            for page in iam.get_paginator("list_users").paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    user_arn = user["Arn"]
                    attached = []
                    admin_policies = []
                    inline_count = 0

                    try:
                        resp = iam.list_attached_user_policies(UserName=username)
                        attached = resp.get("AttachedPolicies", [])
                        for p in attached:
                            if p["PolicyArn"] in ADMIN_POLICIES:
                                admin_policies.append(p["PolicyName"])
                    except ClientError as e:
                        logger.warning(f"Error listing policies for user {username}: {e}")

                    try:
                        inline = iam.list_user_policies(UserName=username)
                        inline_count = len(inline.get("PolicyNames", []))
                    except ClientError:
                        pass

                    is_compliant = len(admin_policies) == 0 and inline_count == 0

                    evidence_items.append(self.observe(
                        resource=user_arn, property="LeastPrivilege", value=is_compliant, expected=True,
                        metadata={"name": username, "type": "user", "attached_policies": len(attached),
                                  "admin_policies": admin_policies, "inline_policies": inline_count},
                        api="iam:ListAttachedUserPolicies,iam:ListUserPolicies", region="global"))
        except ClientError as e:
            logger.error(f"Error listing users: {e}")

        # Check roles
        try:
            for page in iam.get_paginator("list_roles").paginate():
                for role in page["Roles"]:
                    role_name = role["RoleName"]
                    role_arn = role["Arn"]
                    # Skip AWS service-linked roles
                    if role.get("Path", "").startswith("/aws-service-role/"):
                        continue

                    attached = []
                    admin_policies = []
                    inline_count = 0

                    try:
                        resp = iam.list_attached_role_policies(RoleName=role_name)
                        attached = resp.get("AttachedPolicies", [])
                        for p in attached:
                            if p["PolicyArn"] in ADMIN_POLICIES:
                                admin_policies.append(p["PolicyName"])
                    except ClientError:
                        pass

                    try:
                        inline = iam.list_role_policies(RoleName=role_name)
                        inline_count = len(inline.get("PolicyNames", []))
                    except ClientError:
                        pass

                    is_compliant = len(admin_policies) == 0

                    evidence_items.append(self.observe(
                        resource=role_arn, property="LeastPrivilege", value=is_compliant, expected=True,
                        metadata={"name": role_name, "type": "role", "attached_policies": len(attached),
                                  "admin_policies": admin_policies, "inline_policies": inline_count},
                        api="iam:ListAttachedRolePolicies,iam:ListRolePolicies", region="global"))
        except ClientError as e:
            logger.error(f"Error listing roles: {e}")

        return evidence_items


class LeastPrivilegeEvaluator:
    domain = "identity_and_access.authorization.least_privilege"
    assertion = "No IAM users or roles have overprivileged admin access attached directly"

    async def evaluate(self, evidence_items: list[Evidence]) -> EvaluationResult:
        if not evidence_items:
            return EvaluationResult(result=ClaimResult.INDETERMINATE, confidence=0.0,
                                    assessment="No IAM principals found.")

        compliant = []
        non_compliant = []
        admin_users = []
        admin_roles = []
        inline_warnings = []
        caveats = []
        recommendations = []

        for item in evidence_items:
            obs = item.observation if isinstance(item.observation, dict) else {}
            meta = obs.get("metadata", {})
            name = meta.get("name", "unknown")
            ptype = meta.get("type", "unknown")
            is_ok = obs.get("value", False)
            admin = meta.get("admin_policies", [])
            inline = meta.get("inline_policies", 0)

            if is_ok:
                compliant.append(f"{ptype}:{name}")
            else:
                non_compliant.append(f"{ptype}:{name}")
                if admin:
                    (admin_users if ptype == "user" else admin_roles).append(f"{name} ({', '.join(admin)})")
                if inline > 0 and ptype == "user":
                    inline_warnings.append(f"{name} has {inline} inline policy(ies)")

        if admin_users:
            caveats.append(f"Users with admin policies: {', '.join(admin_users)}")
            recommendations.append("Replace AdministratorAccess with scoped policies matching actual job functions")
        if admin_roles:
            caveats.append(f"Roles with admin policies: {', '.join(admin_roles[:5])}")
            if len(admin_roles) > 5:
                caveats.append(f"...and {len(admin_roles)-5} more admin roles")
            recommendations.append("Audit admin roles — restrict to break-glass accounts only")
        if inline_warnings:
            caveats.append(f"Inline policies found: {', '.join(inline_warnings)}")
            recommendations.append("Convert inline policies to managed policies for visibility and reuse")

        total = len(evidence_items)
        pct = len(compliant) / total if total > 0 else 0

        if pct == 1.0:
            conf = min(0.99, 0.85 + 0.14 * min(total / 20, 1.0))
            return EvaluationResult(result=ClaimResult.SATISFIED, confidence=round(conf, 3),
                assessment=f"All {total} IAM principal(s) follow least privilege. No admin policies directly attached.",
                caveats=caveats, evidence_ids=[e.evidence_id for e in evidence_items])
        elif pct > 0.7:
            return EvaluationResult(result=ClaimResult.PARTIAL, confidence=round(pct * 0.85, 3),
                assessment=f"{len(compliant)}/{total} IAM principals follow least privilege. {len(non_compliant)} overprivileged.",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])
        else:
            return EvaluationResult(result=ClaimResult.NOT_SATISFIED, confidence=0.95,
                assessment=f"Only {len(compliant)}/{total} IAM principals follow least privilege.",
                caveats=caveats, recommendations=recommendations,
                evidence_ids=[e.evidence_id for e in evidence_items])


class AWSPrivilegeAgent:
    def __init__(self, agent, region="us-east-2"):
        self.agent = agent
        self.region = region
        self.collector = LeastPrivilegeCollector()
        self.evaluator = LeastPrivilegeEvaluator()

    @classmethod
    def create(cls, region="us-east-2"):
        keys = KeyPair.generate()
        config = __import__('otvp_agent').AgentConfig(agent_id="aws-privilege-agent-v1",
            vendor="OTVP Reference / Killswitch Advisory", version="1.0.0", key_pair=keys,
            domains=["identity_and_access.authorization.least_privilege"])
        return cls(agent=Agent(config), region=region)

    async def run(self, subject="killswitch-advisory", relying_party=None):
        ctx = CollectionContext(environment="test", region=self.region)
        print("=" * 70)
        print("  OTVP Reference Agent: Least Privilege")
        print(f"  Region: global (IAM)")
        print(f"  Subject: {subject}")
        print("=" * 70)
        print()

        evidence = await self.collector.collect(ctx)
        users = sum(1 for e in evidence if (e.observation or {}).get("metadata",{}).get("type")=="user")
        roles = sum(1 for e in evidence if (e.observation or {}).get("metadata",{}).get("type")=="role")
        print(f"  ✓ Collected {len(evidence)} IAM principal evidence items")
        print(f"    Users: {users}")
        print(f"    Roles: {roles}")
        print()

        signed_refs = [self.agent.sign_evidence(ev).evidence_id for ev in evidence]
        result = await self.evaluator.evaluate(evidence)

        print(f"  Evaluation: {result.result.value}")
        print(f"  Confidence: {result.confidence:.0%}")
        print(f"  Assessment: {result.assessment}")
        for c in result.caveats: print(f"  ⚠ Caveat: {c}")
        for r in result.recommendations: print(f"  → Recommendation: {r}")
        print()

        claim = self.agent.create_claim(
            domain=self.evaluator.domain, assertion=self.evaluator.assertion,
            result=result.result, confidence=result.confidence, evidence_refs=signed_refs,
            opinion=result.assessment, caveats=result.caveats, recommendations=result.recommendations,
            scope=ClaimScope(environment="test", services=["IAM"], regions=["global"]))

        envelope = self.agent.build_envelope(claims=[claim], subject=subject, relying_party=relying_party)

        print("─" * 70)
        print(envelope.summary())
        print()
        print("─" * 70)
        print("Verification:")
        print(f"  Envelope signature valid: {self.agent.verify_envelope(envelope)}")
        for c in envelope.claims: print(f"  Claim [{c.claim_id}] signature valid: {self.agent.verify_claim(c)}")
        print(f"  Evidence store size: {self.agent.evidence_store.size}")
        print(f"  Merkle root: {self.agent.evidence_store.root_hash}")
        store = self.agent.evidence_store
        for i in range(min(3, store.size)):
            print(f"  Evidence [{i}] Merkle proof valid: {store.get_proof(i).verify()}")
        print()
        print("─" * 70)
        print("Full Trust Envelope (JSON):")
        print("─" * 70)
        print(envelope.to_json(indent=2))
        output_path = f"trust_envelope_privilege_{subject}.json"
        with open(output_path, "w") as f: f.write(envelope.to_json(indent=2))
        print(f"\n  ✓ Envelope saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="OTVP AWS Least Privilege Agent")
    parser.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "us-east-2"))
    parser.add_argument("--subject", default="killswitch-advisory")
    parser.add_argument("--relying-party", default=None)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    agent = AWSPrivilegeAgent.create(region=args.region)
    asyncio.run(agent.run(subject=args.subject, relying_party=args.relying_party))

if __name__ == "__main__":
    main()
