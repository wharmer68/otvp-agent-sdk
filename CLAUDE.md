# CLAUDE.md — OTVP SDK

## What This Repo Does

The core engine of the Open Transparency Verification Platform. Contains autonomous agents that audit AWS infrastructure against 11 security control criteria mapped to SOC 2 Trust Services Common Criteria.

This is where the actual security verification logic lives. The otvp-app consumes this SDK to run agents and display results.

## The 11 Control Agents

| # | Agent | What It Checks | SOC 2 Mapping |
|---|-------|----------------|---------------|
| 1 | Encryption at Rest | RDS, S3, EBS encryption status | CC6.1, CC6.7 |
| 2 | IAM MFA Enforcement | Console users with/without MFA | CC6.1 |
| 3 | KMS Key Management | Key rotation, CMK vs AWS-managed keys | CC6.1, CC6.7 |
| 4 | Network Segmentation | Security groups, high-risk ports exposed | CC6.1, CC6.6 |
| 5 | Audit Logging | CloudTrail config, VPC flow logs | CC7.1, CC7.2 |
| 6 | Account Lifecycle | Stale accounts, unused access keys | CC6.2, CC6.5 |
| 7 | Encryption in Transit | ALB TLS config, certificate validity | CC6.1, CC6.7 |
| 8 | Ingress Controls | Public attack surface, WAF coverage | CC6.6 |
| 9 | Least Privilege | Admin policy sprawl, inline policies | CC6.3 |
| 10 | Vulnerability Management | SSM patch compliance, Inspector findings | CC7.1 |
| 11 | Backup & Recovery | AWS Backup plans, snapshot coverage | CC7.5, CC9.1 |

## Key Concepts

### Envelopes
An **envelope** is a point-in-time posture snapshot for a specific control. Each agent run produces an envelope containing:
- Control identifier and SOC 2 mapping
- Pass/fail/warning status per resource
- Evidence collected (what was checked, what was found)
- Timestamp and scope

Envelopes are the primary data structure consumed by otvp-app for display.

### Agents
Each control has a dedicated agent that:
1. Authenticates to AWS (read-only IAM permissions)
2. Queries relevant services (EC2, S3, IAM, CloudTrail, etc.)
3. Evaluates findings against defined criteria
4. Produces an envelope with results

**Critical:** Agents are **read-only**. They observe and report. They never modify infrastructure.

## Architecture

```
otvp-sdk/
├── agents/           # One agent per control criterion
├── tests/            # Test suite for each agent
├── models/           # Envelope and finding data structures
├── utils/            # AWS client helpers, shared logic
└── config/           # Control criteria definitions, thresholds
```

<!-- UPDATE: Verify this matches actual directory structure -->

## Development Rules

- **Read-only AWS access** — agents must never use write permissions
- **Least privilege IAM** — each agent should document the minimum IAM permissions it needs
- **No credentials in code** — AWS auth via environment variables, profiles, or IAM roles
- **Deterministic output** — same infrastructure state should produce the same envelope
- **Error handling** — if an agent can't access a resource, it reports "unable to assess" not "pass"
- **Test coverage** — each agent needs tests with mocked AWS responses
- `.gitignore` must include: `.env`, `*.log`, `__pycache__/`, `results/`

## AWS Permissions Model

Agents need read-only access to these AWS services:
- IAM (users, policies, access keys, MFA devices)
- EC2 (security groups, instances, EBS volumes)
- S3 (bucket encryption, policies)
- RDS (encryption status, configurations)
- CloudTrail (trail configs, status)
- KMS (key metadata, rotation status)
- ELBv2 (ALB listeners, TLS configs)
- ACM (certificate status, expiry)
- WAFv2 (web ACL associations)
- SSM (patch compliance)
- Inspector (findings)
- AWS Backup (plans, selections)
- VPC (flow log configs)

**Recommended:** Use a dedicated IAM role with `ReadOnlyAccess` managed policy, scoped down per-agent as the project matures.

## Relationship to Other Repos

- **otvp-app** imports/calls this SDK to run agents and display envelopes
- **otvp** (parent) is the older standalone RLS scanner — narrower scope, Supabase-specific
- **otvp-dashboard** is deprecated static UI — otvp-app replaces it
- See `~/otvp-projects/CLAUDE.md` for full system overview

## Owner Context

Bil Harmer — CISO at Supabase. The SOC 2 mappings are intentional — this tool is designed to provide continuous verification evidence, not just one-time audit snapshots. Think of it as "compliance as code" for AWS security baselines.
