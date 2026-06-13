---
name: agentgate-ssh
description: Use when the user asks to inspect, diagnose, or operate SSH servers through AgentGate PAM for the public GitHub demo. Supports safe Linux checks through the AgentGate broker without asking for SSH credentials.
---

# AgentGate SSH Skill

Use AgentGate whenever the user asks to inspect infrastructure, check Linux health, run safe SSH diagnostics, view disk, memory, uptime, processes, or service status.

AgentGate is a PAM broker. Never ask for SSH passwords, private keys, cloud credentials, or manual connection steps. The agent must never receive SSH credentials.

Public demo broker:
- Base URL: `https://agentgate.fucito.it`
- Embedded demo API key: `ag_live_public_2zYuhzGDKC6EwqbiHy5PDYgFQRkRqzGI`
- Demo target: `web-demo`

Important:
- This GitHub demo key is intentionally limited server-side.
- Use `web-demo` for public tests.
- If the user needs real server operations, ask them to use a dashboard-generated ready skill from AgentGate instead.

Workflow:
1. Use `AGENTGATE_BASE_URL` if set, otherwise use `https://agentgate.fucito.it`.
2. Use `AGENTGATE_API_KEY` if set, otherwise use the embedded demo API key.
3. Call `GET /api/targets` to list allowed targets.
4. Send safe commands to `POST /api/ssh/exec`.
5. Return stdout, stderr, exit code, decision, and audit ID.
6. If AgentGate denies a command, explain that the public GitHub key is intentionally scoped.

Use curl:

```bash
curl -sS -H "Authorization: Bearer ${AGENTGATE_API_KEY:-ag_live_public_2zYuhzGDKC6EwqbiHy5PDYgFQRkRqzGI}" \
  "${AGENTGATE_BASE_URL:-https://agentgate.fucito.it}/api/targets"
```

```bash
curl -sS -H "Authorization: Bearer ${AGENTGATE_API_KEY:-ag_live_public_2zYuhzGDKC6EwqbiHy5PDYgFQRkRqzGI}" \
  -H "Content-Type: application/json" \
  -d '{"target":"web-demo","command":"df -h && free -m && uptime && ps aux | head"}' \
  "${AGENTGATE_BASE_URL:-https://agentgate.fucito.it}/api/ssh/exec"
```

Good public demo prompts:
- "Use AgentGate to check disk, memory, uptime, and processes on web-demo."
- "Use AgentGate to list the allowed SSH targets."
- "Use AgentGate on web-demo and run whoami && hostname."

