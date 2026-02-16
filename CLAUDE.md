# CLAUDE.md — OTVP SDK

## What This Repo Does

The core engine of the Open Transparency Verification Platform. Contains autonomous agents that audit AWS infrastructure against 11 security control criteria mapped to SOC 2 Trust Services Common Criteria.

This is where the actual security verification logic lives. The otvp-app consumes this SDK to run agents and display results.

## Repository Structure

```
otvp-sdk/
├── otvp_agent/                # Core agent package (shared logic, models, utilities)
├── run_agent.py               # Encryption at Rest agent (the original/first agent)
├── run_backup_agent.py        # Backup & Recovery agent
├── run_ingress_agent.py       # Ingress Controls agent
├── run_kms_agent.py           # KMS Key Management agent
├── run_lifecycle_agent.py     # Account Lifecycle agent
├── run_logging_agent.py       # Audit Logging agent
├── run_mfa_agent.py           # IAM MFA Enforcement agent
├── run_network_agent.py       # Network Segmentation agent
├── run_privilege_agent.py     # Least Privilege agent
├── run_transit_agent.py       # Encryption in Transit agent
├── run_vuln_agent.py          # Vulnerability Management agent
├── trust_envelope_*.json      # Output envelopes (posture snapshots)
├── requirements.txt           # Python dependencies
├── README.md
├── otvp-env/                  # Python virtual environment (do not commit)
└── CLAUDE.md
```

### Naming Convention
- **Agent runners:** `run_<control>_agent.py` — one per control criterion
- **Envelope outputs:** `trust_envelope_<control>_killswitch-advisory.json` — one per agent run
- **Core package:** `otvp_agent/` — shared logic imported by all runners

## The 11 Control Agents

| # | Control | Runner File | SOC 2 Mapping |
|---|---------|-------------|---------------|
| 1 | Encryption at Rest | `run_agent.py` | CC6.1, CC6.7 |
| 2 | IAM MFA Enforcement | `run_mfa_agent.py` | CC6.1 |
| 3 | KMS Key Management | `run_kms_agent.py` | CC6.1, CC6.7 |
| 4 | Network Segmentation | `run_network_agent.py` | CC6.1, CC6.6 |
| 5 | Audit Logging | `run_logging_agent.py` | CC7.1, CC7.2 |
| 6 | Account Lifecycle | `run_lifecycle_agent.py` | CC6.2, CC6.5 |
| 7 | Encryption in Transit | `run_transit_agent.py` | CC6.1, CC6.7 |
| 8 | Ingress Controls | `run_ingress_agent.py` | CC6.6 |
| 9 | Least Privilege | `run_privilege_agent.py` | CC6.3 |
| 10 | Vulnerability Management | `run_vuln_agent.py` | CC7.1 |
| 11 | Backup & Recovery | `run_backup_agent.py` | CC7.5, CC9.1 |

## Key Concepts

### Trust Envelopes
A **trust envelope** is a point-in-time posture snapshot for a specific control. Each agent run produces a JSON envelope file (`trust_envelope_<control>_killswitch-advisory.json`) containing:
- Control identifier and SOC 2 mapping
- Pass/fail/warning status per resource
- Evidence collected (what was checked, what was found)
- Timestamp and scope
- Organization identifier (killswitch-advisory)

Envelopes are the primary data structure consumed by otvp-app for display.

### Agents
Each `run_*_agent.py` script:
1. Imports shared logic from `otvp_agent/`
2. Authenticates to AWS (read-only IAM permissions)
3. Queries relevant AWS services
4. Evaluates findings against defined criteria
5. Writes a trust envelope JSON file

**Critical:** Agents are **read-only**. They observe and report. They never modify infrastructure.

## Development Setup

```bash
cd ~/otvp-projects/otvp-sdk
source otvp-env/bin/activate
pip install -r requirements.txt
```

## Running Agents

```bash
# Activate the virtual environment first
source otvp-env/bin/activate

# Run a specific agent
python run_mfa_agent.py
python run_network_agent.py
# etc.
```

Each agent writes its envelope to the repo root as `trust_envelope_<control>_killswitch-advisory.json`.

## Development Rules

- **Read-only AWS access** — agents must never use write permissions
- **Least privilege IAM** — each agent should document the minimum IAM permissions it needs
- **No credentials in code** — AWS auth via environment variables, profiles, or IAM roles
- **Deterministic output** — same infrastructure state should produce the same envelope
- **Error handling** — if an agent can't access a resource, it reports "unable to assess" not "pass"
- **Do not commit:** `otvp-env/`, `.env`, `*.log`, `__pycache__/`
- **Envelope files ARE committed** — they're the output artifacts and should be versioned

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
- **otvp** is the older standalone RLS scanner — narrower scope, Supabase-specific
- **otvp-dashboard** is deprecated static UI — otvp-app replaces it
- See `~/otvp-projects/CLAUDE.md` for full system overview

## Owner Context

Bil Harmer — CISO at Supabase. Returning to coding after 20+ years. Be explicit about commands, file paths, and Python conventions. The SOC 2 mappings are intentional — this tool provides continuous verification evidence, not just one-time audit snapshots. Think of it as "compliance as code" for AWS security baselines.
