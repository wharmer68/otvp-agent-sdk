# CLAUDE.md — OTVP SDK

## What This Repo Does

The reference implementation of the Open Transparency Verification Platform. Contains autonomous Python agents that audit AWS infrastructure against 11 security control criteria mapped to SOC 2 Trust Services Common Criteria, producing trust envelopes as JSON output.

## Repository Structure

```
otvp-sdk/
├── otvp_agent/                    # Core agent package
│   ├── __init__.py                # Package init
│   ├── core.py                    # Core agent logic
│   ├── envelope.py                # Trust envelope data structure and generation
│   ├── claims.py                  # Claim definitions for envelope contents
│   ├── domains.py                 # Domain definitions
│   ├── agents/                    # Agent implementations (per-control logic)
│   ├── crypto/                    # Cryptographic signing/verification for envelopes
│   ├── evidence/                  # Evidence collection and formatting
│   └── query/                     # AWS query helpers
├── run_agent.py                   # Encryption at Rest agent (the original)
├── run_backup_agent.py            # Backup & Recovery agent
├── run_ingress_agent.py           # Ingress Controls agent
├── run_kms_agent.py               # KMS Key Management agent
├── run_lifecycle_agent.py         # Account Lifecycle agent
├── run_logging_agent.py           # Audit Logging agent
├── run_mfa_agent.py               # IAM MFA Enforcement agent
├── run_network_agent.py           # Network Segmentation agent
├── run_privilege_agent.py         # Least Privilege agent
├── run_transit_agent.py           # Encryption in Transit agent
├── run_vuln_agent.py              # Vulnerability Management agent
├── trust_envelope_*.json          # Output envelopes (posture snapshots)
├── requirements.txt               # Python dependencies
├── README.md
├── otvp-env/                      # Python virtual environment (do not commit)
└── CLAUDE.md
```

### Naming Conventions
- **Agent runners:** `run_<control>_agent.py` at repo root (exception: `run_agent.py` is Encryption at Rest, the first agent built)
- **Envelope outputs:** `trust_envelope_<control>_killswitch-advisory.json` at repo root
- **Core package:** `otvp_agent/` contains all shared logic imported by runners

### Package Architecture
- `core.py` — base agent class and execution logic
- `envelope.py` — trust envelope schema, serialization, output
- `claims.py` — defines what claims an envelope can make about a control
- `domains.py` — defines which AWS domains/services each control covers
- `agents/` — per-control agent implementations (the "what to check" logic)
- `crypto/` — envelope signing and verification
- `evidence/` — evidence collection, formatting, and attachment to envelopes
- `query/` — AWS API query helpers shared across agents

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
A **trust envelope** is a point-in-time posture snapshot for a specific control. Each agent run produces a JSON file (`trust_envelope_<control>_killswitch-advisory.json`) containing:
- Control identifier and SOC 2 mapping
- Pass/fail/warning status per resource
- Evidence collected
- Timestamp and scope
- Organization identifier (killswitch-advisory)

### Agents
Each `run_*_agent.py` script:
1. Imports shared logic from `otvp_agent/`
2. Authenticates to AWS (read-only IAM permissions)
3. Queries relevant AWS services
4. Evaluates findings against defined criteria
5. Writes a trust envelope JSON file to the repo root

**Critical:** Agents are **read-only**. They observe and report. They never modify infrastructure.

## Development Setup

```bash
cd ~/otvp-projects/otvp-sdk
source otvp-env/bin/activate
pip install -r requirements.txt
```

## Running Agents

```bash
source otvp-env/bin/activate
python run_mfa_agent.py
python run_network_agent.py
# etc.
```

## Development Rules

- **Read-only AWS access** — agents must never use write permissions
- **No credentials in code** — AWS auth via environment variables, profiles, or IAM roles
- **Deterministic output** — same infrastructure state should produce the same envelope
- **Error handling** — if an agent can't access a resource, report "unable to assess" not "pass"
- **Envelope files ARE committed** — they're output artifacts and should be versioned
- **Do not commit:** `otvp-env/`, `.env`, `*.log`, `__pycache__/`

## AWS Permissions Model

Agents need read-only access to: IAM, EC2, S3, RDS, CloudTrail, KMS, ELBv2, ACM, WAFv2, SSM, Inspector, AWS Backup, VPC.

Recommended: dedicated IAM role with `ReadOnlyAccess`, scoped down per-agent as the project matures.

## Relationship to Other Repos

- **otvp** defines the spec that this SDK implements
- **otvp-app** consumes this SDK to run agents and display envelopes
- **otvp-dashboard** is deprecated static UI
- See `~/otvp-projects/CLAUDE.md` for full system overview

## Owner Context

Bil Harmer — CISO at Supabase. Returning to coding after 20+ years. Be explicit about commands, file paths, and Python conventions. Don't assume familiarity with modern toolchains.
