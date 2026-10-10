# Runbook: Payment API Incident Triage

## Service Metadata
- software: payment-api
- Team: Core Checkout
- Loki Stream: {app="payment-api", env="production"}
- Repository: my-org/payment-api

## Standard Incident Procedures
1. Log Analysis: Query Loki for error logs matching {app="payment-api"} |= "ERROR".
2. Version Verification: Check recent GitHub commits and GitHub Actions deploy runs.
3. Remediation Boundary:
   - NEVER fose or push directly to main.
   - Create fix branch (fix/payment-api-<issue>) and submit a Draft Pull Request.
   - Deployment must proceed through CI/CD review;
   - Secrets and .env files are strictly forbidden.
