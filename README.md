# OTVP Agent SDK — AWS Encryption Agent (Live)

## Quick Start

```bash
# 1. Create virtual environment
python3 -m venv otvp-env
source otvp-env/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure AWS credentials
export AWS_PROFILE=otvp-test
export AWS_DEFAULT_REGION=us-east-2

# 4. Run the agent
python run_agent.py
```

## What It Does

Scans your AWS account for RDS instances, S3 buckets, and EBS volumes.
Evaluates encryption status. Produces a cryptographically signed Trust Envelope.

## Architecture

```
Collect (boto3) → Sign (Ed25519) → Store (Merkle) → Evaluate → Claim → Envelope
```

Only two runtime dependencies: `cryptography` + `boto3`.
