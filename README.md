# TA-IaC — Production AWS CDK Edition

This repository contains a production-ready, AWS-integrable Threat-Aware IaC system built for deployment via AWS CDK (Python).

**Contents**
- `infrastructure/` — CDK app and stack definitions
- `lambdas/` — Submitter & Worker Lambdas and library modules (threat adapters, correlation, scoring)
- `cicd/` — CI runner to generate Terraform plan and call the API
- `deploy.sh` — helper script to deploy via cdk
- `requirements.txt` — Python dependencies for local dev & lambdas

**Quickstart (developer)**
1. Install AWS CDK v2 and Python deps:
   ```bash
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   npm install -g aws-cdk@2
   ```
2. Bootstrap & deploy:
   ```bash
   cdk bootstrap
   ./deploy.sh deploy
   ```
3. After deploy, note the API URL from CDK output. Configure `cicd/ta_iac_runner.py` and your CI with the API URL and API keys.

**Notes**
- Lambdas expect environment variables for AWS resource names and threat feed API keys. See `infrastructure/stack` for variable names.
- This repository uses `aws-cdk-lib` and the CDK Python Lambda packaging for building assets. Adjust to your pipeline as needed.
