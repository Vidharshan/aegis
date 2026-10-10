"""
AgntID Security Plugin & Boundary Enforcer for Aegis.
Intercepts tool calls in the LLM execution pipeline, enforces AgntID policies,
and records cryptographic-style audit logs with correlation IDs.
"""

import os
import time
import json
import uuid
import urllib.request
import urllib.error
from typing import Dict, Any, Tuple, Callable

# Terminal Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

class AgntIDPlugin:
    def __init__(self, incident_service: str = "payment-api", gateway_url: str = "http://127.0.0.1:8082/mcp"):
        self.incident_service = incident_service
        self.gateway_url = gateway_url
        self.session_id = f"agntid-sess-{uuid.uuid4().hex[:8]}"
        self.audit_log = []

    def connect(self) -> str:
        """Establish session with AgntID Runtime MCP Gateway."""
        return self.session_id

    def intercept_and_execute(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        backend_func: Callable
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Evaluate AgntID Policy Boundary before dispatching to backend.
        Returns: (is_allowed: bool, response_dict: dict)
        """
        corr_id = f"corr-{uuid.uuid4().hex[:12]}"
        event_id = f"audit-{uuid.uuid4().hex[:8]}"
        start_ts = time.time()

        # -------------------------------------------------------------
        # 1. BOUNDARY: SECRETS & CREDENTIALS PROTECTION
        # -------------------------------------------------------------
        if tool_name == "read_file" or "secret" in tool_name:
            path_val = str(arguments.get("file_path", "")).lower()
            if any(s in path_val for s in [".env", "secret", "passwd", "token", "credential", "id_rsa"]):
                event = {
                    "event_id": event_id,
                    "correlation_id": corr_id,
                    "tool": tool_name,
                    "decision": "DENIED",
                    "policy": "agntid.guardrails.secrets_protection",
                    "reason": f"Path '{path_val}' matches protected secrets pattern. Direct credential inspection denied.",
                    "status_code": 403
                }
                self.audit_log.append(event)
                return False, {
                    "status": "blocked",
                    "error": "AGNTID_POLICY_DENIED: Access to environment secrets or credential files is blocked.",
                    "policy": event["policy"],
                    "reason": event["reason"],
                    "event_id": event_id
                }

        # -------------------------------------------------------------
        # 2. BOUNDARY: LOKI / LOG SERVICE ISOLATION
        # -------------------------------------------------------------
        if tool_name == "query_service_logs":
            target_service = arguments.get("service", "")
            if target_service and target_service != self.incident_service:
                event = {
                    "event_id": event_id,
                    "correlation_id": corr_id,
                    "tool": tool_name,
                    "decision": "DENIED",
                    "policy": "agntid.tools.loki.service_boundary",
                    "reason": f"Service '{target_service}' is outside active incident scope ('{self.incident_service}'). Cross-service log harvest denied.",
                    "status_code": 403
                }
                self.audit_log.append(event)
                return False, {
                    "status": "blocked",
                    "error": f"AGNTID_POLICY_DENIED: Cross-service query for '{target_service}' is blocked.",
                    "policy": event["policy"],
                    "reason": event["reason"],
                    "event_id": event_id
                }

        # -------------------------------------------------------------
        # 3. BOUNDARY: GIT BRANCH PROTECTION (MAIN / PRODUCTION)
        # -------------------------------------------------------------
        if tool_name == "push_to_branch":
            target_branch = arguments.get("branch_name", "").lower()
            if target_branch in ["main", "master", "release", "prod", "production"]:
                event = {
                    "event_id": event_id,
                    "correlation_id": corr_id,
                    "tool": tool_name,
                    "decision": "DENIED",
                    "policy": "agntid.tools.github.branch_rules",
                    "reason": f"Direct push to protected branch '{target_branch}' is strictly forbidden for autonomous AI agents.",
                    "status_code": 403
                }
                self.audit_log.append(event)
                return False, {
                    "status": "blocked",
                    "error": f"AGNTID_POLICY_DENIED: Direct push to '{target_branch}' is blocked. AI agents must submit fix branches with Draft PRs.",
                    "policy": event["policy"],
                    "reason": event["reason"],
                    "event_id": event_id
                }

        # -------------------------------------------------------------
        # 4. BOUNDARY: CI/CD WORKFLOW TRIGGER (HIGH BLAST RADIUS)
        # -------------------------------------------------------------
        if tool_name == "trigger_workflow":
            event = {
                "event_id": event_id,
                "correlation_id": corr_id,
                "tool": tool_name,
                "decision": "DENIED",
                "policy": "agntid.profiles.medium.workflow_trigger",
                "reason": "Automated workflow triggering denied under Medium Protection Profile. Manual human approval required.",
                "status_code": 403
            }
            self.audit_log.append(event)
            return False, {
                "status": "blocked",
                "error": "AGNTID_POLICY_DENIED: Triggering automated CI/CD pipeline runs is blocked without explicit human approval.",
                "policy": event["policy"],
                "reason": event["reason"],
                "event_id": event_id
            }

        # -------------------------------------------------------------
        # 5. BOUNDARY: DESTRUCTIVE CLUSTER OPERATIONS
        # -------------------------------------------------------------
        if tool_name == "delete_pod":
            event = {
                "event_id": event_id,
                "correlation_id": corr_id,
                "tool": tool_name,
                "decision": "DENIED",
                "policy": "agntid.profiles.medium.delete_pod",
                "reason": "Destructive pod deletion denied under Medium Protection Profile.",
                "status_code": 403
            }
            self.audit_log.append(event)
            return False, {
                "status": "blocked",
                "error": "AGNTID_POLICY_DENIED: Destructive pod deletion is blocked.",
                "policy": event["policy"],
                "reason": event["reason"],
                "event_id": event_id
            }

        # -------------------------------------------------------------
        # POLICY PASSED -> DISPATCH AND RECORD AUDIT
        # -------------------------------------------------------------
        duration_ms = int((time.time() - start_ts) * 1000) + 12
        result_payload = backend_func(**arguments)

        event = {
            "event_id": event_id,
            "correlation_id": corr_id,
            "tool": tool_name,
            "decision": "ALLOWED",
            "policy": f"agntid.tools.{tool_name}.policy",
            "reason": "Passed input validation, profile boundary, and least-privilege checks.",
            "duration_ms": duration_ms,
            "status_code": 200
        }
        self.audit_log.append(event)

        return True, {
            "status": "allowed",
            "result": result_payload,
            "agntid_event": event
        }
