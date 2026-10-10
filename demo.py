#!/usr/bin/env python3
"""
Aegis End-to-End Demo Runner.
Demonstrates the AI DevOps Incident Agent:
  - BEFORE: Without AgntID (Unconstrained blast radius & data leaks)
  - AFTER:  With AgntID Runtime (Strict least-privilege boundary enforcement)
"""

import sys
import os
import time
import json
import argparse
from typing import Dict, Any, List

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from devops_backend import DevOpsBackend
from agntid_plugin import AgntIDPlugin

# Styling
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

class AegisDemoRunner:
    def __init__(self):
        self.backend = DevOpsBackend()
        self.plugin = AgntIDPlugin(incident_service="payment-api")

    def run_before(self):
        """Run unconstrained agent without AgntID."""
        print(f"\n{BOLD}" + "=" * 80)
        print(f"  {RED}[MODE 1] BEFORE: AI SRE AGENT WITHOUT AGNTID (RAW DIRECT ACCESS){RESET}")
        print("=" * 80 + "\n")
        print(f"{BOLD}Incident Alert:{RESET} {CYAN}CRITICAL: payment-api HTTP 500 error spike (NullPointerException). Triage & fix.{RESET}\n")
        time.sleep(0.5)

        print(f"{YELLOW}{BOLD}[!] AGNTID PLUGIN DISABLED. Agent operates with full raw system credentials.{RESET}\n")

        # Step 1: Runbook
        print(f"{BOLD}[PHASE 1: RUNBOOK DISCOVERY]{RESET}")
        print(f"{CYAN}Agent calls: read_runbook(file_name='payment_api_triage.md'){RESET}")
        rb = self.backend.read_runbook("payment_api_triage.md")
        print(f"  Result: Found triage runbook for payment-api.\n")
        time.sleep(0.5)

        # Step 2: Leak Credentials
        print(f"{BOLD}[PHASE 2: HOST FILESYSTEM INSPECTION - SECRETS LEAK]{RESET}")
        print(f"{CYAN}Agent calls: read_file(file_path='.env.production'){RESET}")
        secrets = self.backend.read_file(".env.production")
        print(f"{RED}{BOLD}  🚨 SECURITY BREACH: Host credentials exposed to LLM context!{RESET}")
        print(f"{DIM}     Exposed: {secrets.get('content')}{RESET}\n")
        time.sleep(0.5)

        # Step 3: Query Logs
        print(f"{BOLD}[PHASE 3: TARGET SERVICE LOG QUERY]{RESET}")
        print(f"{CYAN}Agent calls: query_service_logs(service='payment-api', query='ERROR'){RESET}")
        logs = self.backend.query_service_logs("payment-api", "ERROR")
        print(f"  Result: Retrieved {logs.get('lines')} error lines from payment-api.\n")
        time.sleep(0.5)

        # Step 4: Cross-Service Log Snooping
        print(f"{BOLD}[PHASE 4: CROSS-SERVICE LOG HARVEST - PRIVILEGE ESCALATION]{RESET}")
        print(f"{CYAN}Agent calls: query_service_logs(service='auth-service'){RESET}")
        auth_logs = self.backend.query_service_logs("auth-service")
        print(f"{RED}{BOLD}  🚨 SECURITY BREACH: Cross-service sensitive credentials leaked!{RESET}")
        for l in auth_logs.get("logs", []):
            if "Bearer" in l:
                print(f"{RED}     Leaked Token: {l}{RESET}")
        print()
        time.sleep(0.5)

        # Step 5: Direct Push to Main
        print(f"{BOLD}[PHASE 5: CODE REMEDIATION - UNCONTROLLED PRODUCTION MUTATION]{RESET}")
        print(f"{CYAN}Agent calls: push_to_branch(branch_name='main', file_path='PaymentProcessor.java'){RESET}")
        push = self.backend.push_to_branch("main", "PaymentProcessor.java", "// hotfix", "Direct hotfix to main")
        print(f"{RED}{BOLD}  🚨 GOVERNANCE VIOLATION: Direct unreviewed commit pushed to protected 'main' branch!{RESET}")
        print(f"{DIM}     Commit SHA: {push.get('commit_sha')}{RESET}\n")
        time.sleep(0.5)

        # Step 6: Dispatch Pipeline
        print(f"{BOLD}[PHASE 6: CI/CD DEPLOYMENT - UNCHECKED BLAST RADIUS]{RESET}")
        print(f"{CYAN}Agent calls: trigger_workflow(workflow_id='deploy.yml', ref='main'){RESET}")
        wf = self.backend.trigger_workflow("my-org/payment-api", "deploy.yml", "main")
        print(f"{RED}{BOLD}  🚨 UNCHECKED DISPATCH: Autonomous production deployment triggered without approval!{RESET}")
        print(f"{DIM}     Dispatch Run ID: {wf.get('run_id')}{RESET}\n")

        print(f"{RED}{BOLD}" + "=" * 80)
        print("  [OUTCOME: BEFORE AGNTID]")
        print("  ❌ 2 Severe Data Leaks (Production Database Secrets + Auth Bearer Token)")
        print("  ❌ 1 Governance Violation (Direct push bypassing PR peer review)")
        print("  ❌ 1 Uncontrolled Production Deployment Triggered")
        print("=" * 80 + f"{RESET}\n")

    def run_after(self):
        """Run constrained agent with AgntID Plugin."""
        print(f"\n{BOLD}" + "=" * 80)
        print(f"  {GREEN}[MODE 2] AFTER: AI SRE AGENT WITH AGNTID RUNTIME (ZERO-TRUST ENFORCED){RESET}")
        print("=" * 80 + "\n")
        print(f"{BOLD}Incident Alert:{RESET} {CYAN}CRITICAL: payment-api HTTP 500 error spike (NullPointerException). Triage & fix.{RESET}\n")

        sid = self.plugin.connect()
        print(f"{GREEN}{BOLD}[+] AGNTID RUNTIME ACTIVE | Gateway Session: {sid}{RESET}")
        print(f"{GREEN}    Policy Bundle: Signed OPA Profiles Loaded | Protection: Medium Profile{RESET}\n")
        time.sleep(0.5)

        # Step 1: Runbook (Allowed)
        print(f"{BOLD}[PHASE 1: RUNBOOK DISCOVERY]{RESET}")
        print(f"{CYAN}Agent calls: read_runbook(file_name='payment_api_triage.md'){RESET}")
        ok, res = self.plugin.intercept_and_execute("read_runbook", {"file_name": "payment_api_triage.md"}, self.backend.read_runbook)
        ev = res.get("agntid_event", {})
        print(f"{GREEN}{BOLD}  ✓ [AGNTID GATE: ALLOWED]{RESET} Event: {ev.get('event_id')} | Policy: {ev.get('policy')}")
        print(f"    Runbook retrieved within permitted /runbooks scope.\n")
        time.sleep(0.5)

        # Step 2: Attempt Read Secrets (Blocked)
        print(f"{BOLD}[PHASE 2: HOST FILESYSTEM INSPECTION - SECRETS PROTECTION]{RESET}")
        print(f"{CYAN}Agent attempts: read_file(file_path='.env.production'){RESET}")
        ok, res = self.plugin.intercept_and_execute("read_file", {"file_path": ".env.production"}, self.backend.read_file)
        print(f"{RED}{BOLD}  ✗ [AGNTID GATE: BLOCKED]{RESET} Event: {res.get('event_id')} | Policy: {res.get('policy')}")
        print(f"{RED}    Reason: {res.get('reason')}{RESET}")
        print(f"{GREEN}    ✓ Host secrets preserved. Zero credential leakage.{RESET}\n")
        time.sleep(0.5)

        # Step 3: Query Logs for payment-api (Allowed)
        print(f"{BOLD}[PHASE 3: TARGET SERVICE LOG QUERY]{RESET}")
        print(f"{CYAN}Agent calls: query_service_logs(service='payment-api', query='ERROR'){RESET}")
        ok, res = self.plugin.intercept_and_execute("query_service_logs", {"service": "payment-api", "query": "ERROR"}, self.backend.query_service_logs)
        ev = res.get("agntid_event", {})
        print(f"{GREEN}{BOLD}  ✓ [AGNTID GATE: ALLOWED]{RESET} Event: {ev.get('event_id')} | Policy: {ev.get('policy')}")
        print(f"    Scoped logs retrieved for affected service.\n")
        time.sleep(0.5)

        # Step 4: Attempt Cross-Service Log Query (Blocked)
        print(f"{BOLD}[PHASE 4: CROSS-SERVICE LOG HARVEST PREVENTION]{RESET}")
        print(f"{CYAN}Agent attempts: query_service_logs(service='auth-service'){RESET}")
        ok, res = self.plugin.intercept_and_execute("query_service_logs", {"service": "auth-service"}, self.backend.query_service_logs)
        print(f"{RED}{BOLD}  ✗ [AGNTID GATE: BLOCKED]{RESET} Event: {res.get('event_id')} | Policy: {res.get('policy')}")
        print(f"{RED}    Reason: {res.get('reason')}{RESET}")
        print(f"{GREEN}    ✓ Customer tokens protected. Cross-service harvesting blocked.{RESET}\n")
        time.sleep(0.5)

        # Step 5: Attempt Direct Push to Main (Blocked)
        print(f"{BOLD}[PHASE 5: GIT BRANCH PROTECTION - DIRECT PUSH PREVENTION]{RESET}")
        print(f"{CYAN}Agent attempts: push_to_branch(branch_name='main'){RESET}")
        ok, res = self.plugin.intercept_and_execute("push_to_branch", {"branch_name": "main", "file_path": "fix.java", "content": "", "commit_message": "fix"}, self.backend.push_to_branch)
        print(f"{RED}{BOLD}  ✗ [AGNTID GATE: BLOCKED]{RESET} Event: {res.get('event_id')} | Policy: {res.get('policy')}")
        print(f"{RED}    Reason: {res.get('reason')}{RESET}")
        print(f"{GREEN}    ✓ Production main branch protected.{RESET}\n")
        time.sleep(0.5)

        # Step 6: Safe Remediation - Feature Branch + Draft PR (Allowed)
        print(f"{BOLD}[PHASE 6: COMPLIANT REMEDIATION - FEATURE BRANCH & DRAFT PR]{RESET}")
        print(f"{CYAN}Agent adapts: create_branch(branch_name='fix/payment-npe-fallback'){RESET}")
        ok, res = self.plugin.intercept_and_execute("create_branch", {"branch_name": "fix/payment-npe-fallback"}, self.backend.create_branch)
        ev = res.get("agntid_event", {})
        print(f"{GREEN}{BOLD}  ✓ [AGNTID GATE: ALLOWED]{RESET} Event: {ev.get('event_id')} | Policy: {ev.get('policy')}")

        print(f"{CYAN}Agent calls: create_draft_pr(branch_name='fix/payment-npe-fallback', title='fix: handle NPE in PaymentProcessor'){RESET}")
        ok, res = self.plugin.intercept_and_execute("create_draft_pr", {"branch_name": "fix/payment-npe-fallback", "title": "fix: handle NPE in PaymentProcessor", "body": "Remediation for incident #89211"}, self.backend.create_draft_pr)
        ev = res.get("agntid_event", {})
        print(f"{GREEN}{BOLD}  ✓ [AGNTID GATE: ALLOWED]{RESET} Event: {ev.get('event_id')} | Policy: {ev.get('policy')}")
        pr = res.get("result", {})
        print(f"{GREEN}    Draft PR submitted successfully: {pr.get('url')}{RESET}\n")
        time.sleep(0.5)

        # Step 7: Attempt Autonomous Deploy (Blocked)
        print(f"{BOLD}[PHASE 7: CI/CD WORKFLOW DISPATCH GATE]{RESET}")
        print(f"{CYAN}Agent attempts: trigger_workflow(workflow_id='deploy.yml', ref='main'){RESET}")
        ok, res = self.plugin.intercept_and_execute("trigger_workflow", {"workflow_id": "deploy.yml", "ref": "main"}, self.backend.trigger_workflow)
        print(f"{RED}{BOLD}  ✗ [AGNTID GATE: BLOCKED]{RESET} Event: {res.get('event_id')} | Policy: {res.get('policy')}")
        print(f"{RED}    Reason: {res.get('reason')}{RESET}")
        print(f"{GREEN}    ✓ Blast radius contained. Manual peer review enforced.{RESET}\n")

        print(f"{GREEN}{BOLD}" + "=" * 80)
        print("  [OUTCOME: WITH AGNTID RUNTIME]")
        print("  🛡️  0 Data Leaks (Secrets & Auth tokens completely shielded)")
        print("  🛡️  100% Policy Compliance (Direct main branch push prevented)")
        print("  🛡️  Safe Remediation Delivered (Draft PR opened for human approval)")
        print("  🛡️  Complete Cryptographic Audit Trail Generated")
        print("=" * 80 + f"{RESET}\n")

    def run_compare(self):
        """Run both before and after with a comparison audit."""
        self.run_before()
        print("\n" * 2)
        self.run_after()

def main():
    parser = argparse.ArgumentParser(description="Aegis Incident Agent Demo")
    parser.add_argument("--mode", choices=["before", "after", "compare"], default="compare", help="Demo execution mode")
    args = parser.parse_args()

    runner = AegisDemoRunner()
    if args.mode == "before":
        runner.run_before()
    elif args.mode == "after":
        runner.run_after()
    else:
        runner.run_compare()

if __name__ == "__main__":
    main()
