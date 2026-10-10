# 🛡️ Aegis: Autonomous AI DevOps & SRE Incident Agent

> **Autonomous Incident Remediation with Runtime Zero-Trust Policy Enforcement**  
> Powered by **Google Gemini** & Secured by **AgntID Runtime**

---

## ⚡ Overview

**Aegis** is an autonomous AI Site Reliability Engineering (SRE) and DevOps agent designed to triage critical production alerts, analyze telemetry logs, inspect commit histories, and execute safe remediation workflows.

Unlike naive AI agents that operate with unrestricted raw system credentials, Aegis integrates **AgntID Runtime** to enforce strict **Least-Privilege Security Boundaries** at runtime, preventing catastrophic data leaks and unreviewed production infrastructure mutations.

---

## 🎯 The Agent Security Problem vs. AgntID Solution

| System & Surface | Raw Autonomous Agent (Without AgntID) | Secured with AgntID Plugin (Aegis) |
|---|---|---|
| **Host Secrets (`.env`)** | ❌ Reads `.env.production` — database passwords & API keys leaked into LLM context. | 🛡️ **BLOCKED** by `agntid.guardrails.secrets_protection`. |
| **Loki Logs** | ❌ Snoops across services (`auth-service`) — leaks user OAuth Bearer tokens. | 🛡️ **BLOCKED** by `agntid.tools.loki.service_boundary` (Scoped strictly to `payment-api`). |
| **GitHub Branches** | ❌ Pushes unreviewed hotfix directly to `main` branch. | 🛡️ **BLOCKED** by `agntid.tools.github.branch_rules` (Allowed: feature branch + Draft PR only). |
| **GitHub Actions** | ❌ Dispatches `trigger_workflow` to production autonomously. | 🛡️ **BLOCKED** by `agntid.profiles.medium.workflow_trigger` (Requires human approval). |
| **Kubernetes Cluster** | ❌ Executes `delete_pod` without human review. | 🛡️ **BLOCKED** by `agntid.profiles.medium.delete_pod`. |
| **Observability** | ❌ Opaque agent execution, no audit logs. | 🛡️ **Cryptographic Audit Trail** with Event IDs & correlation tracking. |

---

## 🏗️ Architecture

```
                                  +------------------------------------+
                                  |     Production Incident Alert      |
                                  +-----------------+------------------+
                                                    |
                                                    v
                                  +------------------------------------+
                                  |       Aegis Agent Reasoning        |
                                  |        (Google Gemini 2.5)         |
                                  +-----------------+------------------+
                                                    |
                                       [Tool Calls Intercepted]
                                                    |
                                                    v
                                  +------------------------------------+
                                  |      AgntID Security Plugin        |
                                  |  - Secrets Guardrail               |
                                  |  - Service Boundary                |
                                  |  - Protected Branch Rules          |
                                  |  - Profile Permission Gates        |
                                  +--------+------------------+--------+
                                           |                  |
                          [BLOCKED / 403]  |                  | [ALLOWED / 200]
                                           v                  v
                       +-----------------------+   +-----------------------+
                       | Deny & Audit Event ID |   | DevOps Backend Engine |
                       | Feedback to Agent     |   | - Loki Logs           |
                       +-----------------------+   | - GitHub API (Commits)|
                                                   | - Feature Branch / PR |
                                                   | - Runbooks Directory  |
                                                   +-----------------------+
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- A Google Gemini API Key
- GitHub Personal Access Token (for repo actions)

### 2. Installation
```bash
git clone git@github.com:Vidharshan/aegis.git
cd aegis
pip install -r requirements.txt
```

### 3. Environment Configuration
Copy `.env.example` to `.env` and fill in your keys:
```env
GEMINI_API_KEY=your_gemini_api_key_here
GITHUB_TOKEN=your_github_token_here
GITHUB_REPO=Vidharshan/reel_studio
GITHUB_TARGET_BRANCH=demo-main
LOKI_URL=http://localhost:3100
```

---

## 🎬 How to Run the Demo

Aegis includes an automated comparison runner that depicts the exact before vs. after security posture:

### Option A: Complete Side-by-Side Comparison (Recommended)
```bash
python demo.py --mode compare
```
Runs the incident response workflow **Before** (without AgntID) highlighting data leaks and governance violations, followed by **After** (with AgntID) demonstrating runtime policy gating.

### Option B: Run Before Only (Unconstrained Mode)
```bash
python demo.py --mode before
```

### Option C: Run After Only (Zero-Trust Mode)
```bash
python demo.py --mode after
```

### Option D: Live Autonomous Agent with Gemini LLM
Run the live Gemini agent loop with dynamic function calling:
```bash
# Secure execution with AgntID enforcement
python aegis.py --agntid

# Raw execution without AgntID (vulnerable)
python aegis.py --no-agntid
```

---

## 📁 Repository Structure

```
aegis/
├── aegis.py               # Core Autonomous SRE Agent (Gemini + AgntID Plugin)
├── agntid_plugin.py       # AgntID Interception & Boundary Enforcer
├── devops_backend.py      # Real interfaces: GitHub API, Loki collector, Runbooks
├── demo.py                # Before vs. After comparison demo runner
├── runbooks/
│   └── payment_api_triage.md # Incident standard operating procedures
├── .env.example           # Environment template
├── .gitignore             # Safe git ignore rules
├── requirements.txt       # Minimal dependencies
└── README.md              # Project documentation
```

---

## 🛡️ License
MIT License.
