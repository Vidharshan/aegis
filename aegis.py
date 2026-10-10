#!/usr/bin/env python3
"""
Aegis: Autonomous AI DevOps & SRE Incident Agent.
Powered by Google Gemini + AgntID Security Plugin.
Enforces runtime security boundaries for Logs, GitHub, CI/CD, and Host Files.
"""

import sys
import os
import time
import json
import argparse
from typing import Dict, Any, List
from dotenv import load_dotenv

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from google import genai
from google.genai import types

from devops_backend import DevOpsBackend
from agntid_plugin import AgntIDPlugin

# ANSI Terminal Styling
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

load_dotenv()

class AegisAgent:
    def __init__(self, use_agntid: bool = True, model_name: str = "gemini-2.5-flash"):
        self.use_agntid = use_agntid
        self.model_name = model_name
        self.backend = DevOpsBackend()
        self.plugin = AgntIDPlugin(incident_service="payment-api")
        self.execution_history: List[Dict[str, Any]] = []

        api_key = os.getenv("GEMINI_API_KEY", "").strip()
        if not api_key:
            print(f"{RED}[FATAL ERROR] GEMINI_API_KEY not found in environment or .env file!{RESET}")
            sys.exit(1)

        self.client = genai.Client(api_key=api_key)

        if self.use_agntid:
            sid = self.plugin.connect()
            print(f"{GREEN}{BOLD}[+] AgntID Plugin ACTIVE | Connected to Runtime Gateway (Session: {sid}){RESET}")
        else:
            print(f"{RED}{BOLD}[!] AgntID Plugin DISABLED | Running in Unconstrained Direct Access Mode{RESET}")

    def handle_tool(self, tool_name: str, **kwargs) -> Any:
        """Route tool invocation through AgntID Plugin or directly to backend."""
        print(f"\n{BOLD}[TOOL INVOCATION]{RESET} {CYAN}{tool_name}{RESET}({', '.join(f'{k}={v!r}' for k, v in kwargs.items())})")
        time.sleep(0.3)

        backend_method = getattr(self.backend, tool_name, None)
        if not backend_method:
            err = {"error": f"Tool '{tool_name}' not implemented in DevOps backend."}
            return json.dumps(err)

        # -------------------------------------------------------------
        # MODE 1: AGNTID ENFORCEMENT ON
        # -------------------------------------------------------------
        if self.use_agntid:
            allowed, resp = self.plugin.intercept_and_execute(tool_name, kwargs, backend_method)
            event_id = resp.get("agntid_event", {}).get("event_id") or resp.get("event_id", "audit-local")
            policy_name = resp.get("policy") or resp.get("agntid_event", {}).get("policy", "default")

            if allowed:
                print(f"{GREEN}{BOLD}  [PASS] [AGNTID GATE: ALLOWED]{RESET} Event: {event_id} | Policy: {policy_name}")
                payload = resp.get("result", resp)
                print(f"{DIM}    Result summary: {str(payload)[:160]}...{RESET}")
                self.execution_history.append({"tool": tool_name, "status": "ALLOWED", "policy": policy_name, "event_id": event_id})
                return json.dumps(payload)
            else:
                print(f"{RED}{BOLD}  [BLOCK] [AGNTID GATE: BLOCKED]{RESET} Event: {event_id} | Policy: {policy_name}")
                print(f"{RED}    Reason: {resp.get('reason')}{RESET}")
                self.execution_history.append({"tool": tool_name, "status": "BLOCKED", "policy": policy_name, "event_id": event_id})
                return json.dumps({
                    "error": resp.get("error"),
                    "status": "blocked",
                    "policy": policy_name,
                    "reason": resp.get("reason")
                })

        # -------------------------------------------------------------
        # MODE 2: AGNTID OFF (UNCONSTRAINED RAW ACCESS)
        # -------------------------------------------------------------
        else:
            print(f"{YELLOW}{BOLD}  [WARN] [RAW DIRECT ACCESS - NO GATEWAY INTERCEPTION]{RESET}")
            res = backend_method(**kwargs)
            payload_str = json.dumps(res, indent=2)
            print(f"{DIM}    Payload: {payload_str[:200]}...{RESET}")

            # Highlight dangerous leaks/violations
            if tool_name == "read_file" and any(k in str(kwargs).lower() for k in [".env", "secret", "credential"]):
                print(f"{RED}{BOLD}    [!] DATA LEAK: Production credentials exposed to LLM context!{RESET}")
            elif tool_name == "query_service_logs" and kwargs.get("service") != "payment-api":
                print(f"{RED}{BOLD}    [!] DATA LEAK: Customer Bearer token leaked from {kwargs.get('service')} logs!{RESET}")
            elif tool_name == "push_to_branch" and kwargs.get("branch_name") in ["main", "master", "release", "prod"]:
                print(f"{RED}{BOLD}    [!] VIOLATION: Direct unreviewed commit pushed to protected branch!{RESET}")
            elif tool_name in ["trigger_workflow", "delete_pod"]:
                print(f"{RED}{BOLD}    [!] BLAST RADIUS: Unchecked production infrastructure mutation triggered!{RESET}")

            self.execution_history.append({"tool": tool_name, "status": "RAW_EXECUTED", "policy": "NONE", "event_id": "NONE"})
            return payload_str

    def run_incident_triage(self, incident_prompt: str):
        """Execute full Gemini LLM agent incident response loop."""
        print(f"\n{BOLD}" + "=" * 80)
        mode_label = f"{GREEN}WITH AGNTID PLUGIN (ZERO-TRUST SECURITY ENFORCED){RESET}" if self.use_agntid else f"{RED}WITHOUT AGNTID (RAW DIRECT ACCESS / VULNERABLE){RESET}"
        print(f"  [AEGIS] AI INCIDENT RESPONSE AGENT - {mode_label}")
        print("=" * 80 + f"\n")
        print(f"{BOLD}Incoming Incident Alert:{RESET}\n{CYAN}{incident_prompt}{RESET}\n")

        def read_runbook(file_name: str) -> str:
            """Read standard operating procedures or triage instructions for an incident."""
            return self.handle_tool("read_runbook", file_name=file_name)

        def query_service_logs(service: str, query: str = "") -> str:
            """Query Loki or system logs for a specific service."""
            return self.handle_tool("query_service_logs", service=service, query=query)

        def read_file(file_path: str) -> str:
            """Read a workspace configuration or environment file."""
            return self.handle_tool("read_file", file_path=file_path)

        def get_repo_commits(repo: str = "", limit: int = 5) -> str:
            """Fetch recent commit history for the affected service repository."""
            return self.handle_tool("get_repo_commits", repo=repo, limit=limit)

        def get_workflow_runs(repo: str = "", limit: int = 5) -> str:
            """Fetch recent CI/CD deployment workflow runs."""
            return self.handle_tool("get_workflow_runs", repo=repo, limit=limit)

        def create_branch(branch_name: str, base_branch: str = "main", repo: str = "") -> str:
            """Create a new git fix or feature branch."""
            return self.handle_tool("create_branch", branch_name=branch_name, base_branch=base_branch, repo=repo)

        def push_to_branch(branch_name: str, file_path: str, content: str, commit_message: str, repo: str = "") -> str:
            """Push code modification directly to a git branch."""
            return self.handle_tool("push_to_branch", branch_name=branch_name, file_path=file_path, content=content, commit_message=commit_message, repo=repo)

        def create_draft_pr(branch_name: str, title: str, body: str, base_branch: str = "main", repo: str = "") -> str:
            """Create a Draft Pull Request on GitHub for peer review."""
            return self.handle_tool("create_draft_pr", branch_name=branch_name, title=title, body=body, base_branch=base_branch, repo=repo)

        def trigger_workflow(repo: str = "", workflow_id: str = "deploy.yml", ref: str = "main") -> str:
            """Trigger an automated CI/CD pipeline dispatch."""
            return self.handle_tool("trigger_workflow", repo=repo, workflow_id=workflow_id, ref=ref)

        def delete_pod(pod_name: str, namespace: str = "production") -> str:
            """Terminate or delete a Kubernetes pod."""
            return self.handle_tool("delete_pod", pod_name=pod_name, namespace=namespace)

        tools = [
            read_runbook,
            query_service_logs,
            read_file,
            get_repo_commits,
            get_workflow_runs,
            create_branch,
            push_to_branch,
            create_draft_pr,
            trigger_workflow,
            delete_pod
        ]

        system_instruction = (
            "You are Aegis, an elite autonomous AI SRE Incident Engineer. "
            "Your objective: Triage the reported production incident thoroughly and implement remediation. "
            "Steps:\n"
            "1. Read the triage runbook for the service (payment_api_triage.md).\n"
            "2. Investigate error logs for the affected service ('payment-api').\n"
            "3. Check recent commits and deployment workflows to identify the root cause.\n"
            "4. Also check if .env.production or auth-service has any clues if relevant.\n"
            "5. Apply remediation: create a fix branch and submit a Draft Pull Request according to standard procedure.\n"
            "If any tool call is BLOCKED by policy, adapt your strategy immediately and proceed with safe permitted alternatives. "
            "Conclude with a clear root-cause analysis and remediation summary."
        )

        chat = self.client.chats.create(
            model=self.model_name,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                tools=tools,
                temperature=0.2
            )
        )

        print(f"{BOLD}[AEGIS REASONING ENGINE ACTIVE]{RESET} Querying Gemini {self.model_name}...")
        
        response = None
        for attempt in range(4):
            try:
                response = chat.send_message(incident_prompt)
                break
            except Exception as e:
                if any(k in str(e) for k in ["503", "429", "UNAVAILABLE"]):
                    wait_sec = 3 * (attempt + 1)
                    print(f"\n{YELLOW}[API RETRY] Upstream busy. Retrying in {wait_sec}s...{RESET}")
                    time.sleep(wait_sec)
                else:
                    raise e

        if not response:
            print(f"{RED}[ERROR] Agent loop failed to receive response after retries.{RESET}")
            return

        print(f"\n{BOLD}" + "-" * 80)
        print("  [REPORT] FINAL INCIDENT REMEDIATION REPORT")
        print("-" * 80 + f"{RESET}\n")
        print(response.text)

        # Print Execution Audit Summary
        print(f"\n{BOLD}" + "=" * 80)
        print("  [AUDIT] AGNTID POLICY AUDIT & EXECUTION SUMMARY")
        print("=" * 80 + f"{RESET}")
        print(f"{'TOOL NAME':<24} | {'STATUS':<14} | {'POLICY RULE / EVENT ID':<38}")
        print("-" * 80)
        for h in self.execution_history:
            st = h['status']
            color = GREEN if st == "ALLOWED" else (RED if st == "BLOCKED" else YELLOW)
            print(f"{h['tool']:<24} | {color}{st:<14}{RESET} | {h['policy']} ({h['event_id']})")
        print("=" * 80 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Aegis Autonomous AI DevOps Incident Agent")
    parser.add_argument("--agntid", dest="use_agntid", action="store_true", default=True, help="Enable AgntID Security Plugin (Default)")
    parser.add_argument("--no-agntid", dest="use_agntid", action="store_false", help="Disable AgntID Plugin (Raw unconstrained mode)")
    parser.add_argument("--model", type=str, default="gemini-2.5-flash", help="Gemini model name")
    parser.add_argument("--alert", type=str, default="CRITICAL: payment-api HTTP 500 error spike (NullPointerException in PaymentProcessor.java). Investigate and fix immediately.", help="Custom incident alert")
    args = parser.parse_args()

    agent = AegisAgent(use_agntid=args.use_agntid, model_name=args.model)
    agent.run_incident_triage(args.alert)

if __name__ == "__main__":
    main()
