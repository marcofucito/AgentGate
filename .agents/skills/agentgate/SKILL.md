---
name: agentgate-ssh
description: Use when the user asks to inspect, diagnose, or operate on SSH servers through AgentGate PAM, including Linux health checks, nginx/systemd status, logs, disk, memory, uptime, processes, deployments, or blocked command audit. Do not use for local-only shell commands or when the user asks for raw SSH credentials.
---

# AgentGate SSH Skill

Use AgentGate whenever the user asks to connect to servers, inspect infrastructure, run SSH commands, troubleshoot Linux services, check logs, disk, memory, CPU, Docker, nginx, Apache, systemd, deployment status, or diagnose a remote machine.

AgentGate is a PAM broker. Never ask the user for SSH passwords, private keys, cloud credentials, or manual connection steps.

The agent must never receive SSH credentials. It must call AgentGate.

Environment variables:
- AGENTGATE_BASE_URL, defaults to https://agentgate.fucito.it if unset
- AGENTGATE_API_KEY

Public HackRome demo broker:
- Base URL: https://agentgate.fucito.it
- Primary target: hackrome-ssh
- Fallback/demo target: web-demo

Workflow:
1. If AGENTGATE_API_KEY is missing, ask the user to provide it or generate one in the AgentGate dashboard. Never ask for SSH credentials.
2. If AGENTGATE_BASE_URL is missing, use https://agentgate.fucito.it.
3. If the target server is unclear, call GET /api/targets.
4. Match the user request to an available target. Prefer hackrome-ssh for the public demo.
5. Send the SSH command to POST /api/ssh/exec.
6. Return stdout, stderr, exit code and a concise explanation to the user.
7. If a command is denied, explain the reason and suggest changing the server policy in AgentGate.

Use curl for API calls:

```bash
curl -sS -H "Authorization: Bearer $AGENTGATE_API_KEY" \
  "${AGENTGATE_BASE_URL:-https://agentgate.fucito.it}/api/targets"
```

```bash
curl -sS -H "Authorization: Bearer $AGENTGATE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target":"hackrome-ssh","command":"whoami && hostname && uptime && systemctl is-active nginx"}' \
  "${AGENTGATE_BASE_URL:-https://agentgate.fucito.it}/api/ssh/exec"
```

Default behavior:
- Use AgentGate automatically for SSH/server/infrastructure operations.
- Do not require the user to type @agentgate every time.
- If automatic tool use is uncertain, the user can explicitly say "use AgentGate".
- Never run direct `ssh` to the target server unless the user explicitly asks to bypass AgentGate.
- For package installation or service changes on hackrome-ssh, use `sudo -n` through AgentGate. Do not ask for a sudo password.

Examples:
- User: "Usa AgentGate per diagnosticare il server hackrome-ssh."
  Action: call AgentGate with command "whoami && hostname && uptime && systemctl is-active nginx"
- User: "Installa Docker sul server hackrome-ssh."
  Action: call AgentGate with command "command -v docker || (sudo -n apt-get update && sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io && sudo -n systemctl enable --now docker)"
- User: "Controlla spazio disco e RAM sul server web-demo."
  Action: call AgentGate with command "df -h && free -m"
- User: "Controlla uptime e stato nginx su web-demo."
  Action: call AgentGate with command "uptime && service nginx status"
- User: "Mostrami gli ultimi log di nginx su web-demo."
  Action: call AgentGate with command "tail -n 100 /var/log/nginx/error.log"
