# AgentGate

Cloud PAM broker for Codex and AI coding agents.

## One-liner

AgentGate lets Codex operate on SSH servers without ever receiving SSH passwords, private keys, or cloud credentials.

## Problem

AI coding agents are becoming infrastructure operators. They can debug servers and fix production issues, but giving them SSH passwords or private keys is unsafe.

## Solution

Developers onboard SSH targets once, generate an AgentGate API key, and Codex can operate through the broker. The agent never sees SSH credentials. Admins get a web dashboard, per-server command rules, and a complete audit trail.

## Architecture

```text
Codex App / Codex Skill
        -> HTTPS + API key
AgentGate Cloud PAM Broker
        -> SSH
Target Server
        -> stdout/stderr/exit code
AgentGate
        -> JSON response + audit log
Codex
```

## Setup

```bash
docker compose up --build
```

Before running a public demo, set a strong admin password:

```bash
export AGENTGATE_ADMIN_EMAIL=admin@example.com
export AGENTGATE_ADMIN_PASSWORD='replace-with-a-long-random-password'
docker compose up --build
```

Open http://localhost:8000 and log in with those credentials. The hosted demo uses a rotated strong password and a rotated magic link for judging speed.

The demo SSH target is created automatically:

```text
Name: web-demo
Host: demo-ssh
Port: 22
Username: demo
Password: demo
```

A real external SSH target can also be onboarded:

```text
Name: hackrome-ssh
Host: 157.230.182.249
Port: 22
Username: agentgate
Auth: private_key
```

## Demo flow

1. Open the AgentGate dashboard.
2. Show the onboarded `web-demo` server.
3. Generate a Codex API key in `API Keys`.
4. Open `Codex Integration` and show `/skill/agentgate.md`.
5. Show that the Codex-ready skill is also committed at `.agents/skills/agentgate/SKILL.md` and `.codex/skills/agentgate/SKILL.md`.
6. Ask Codex:

```text
Usa AgentGate per diagnosticare il server hackrome-ssh: controlla utente, hostname, uptime e stato nginx.
```

7. AgentGate executes SSH and returns stdout/stderr/exit code.
8. Show the audit log.
9. Add or confirm the deny pattern `rm -rf`.
10. Ask for a dangerous command and show AgentGate blocking it.

## API

All API routes use:

```text
Authorization: Bearer <AGENTGATE_API_KEY>
```

Routes:

- `GET /health`
- `GET /api/targets`
- `POST /api/ssh/exec`
- `GET /api/audit`
- `GET /skill/agentgate.md`

## Install the Codex skill

The public HackRome skill is available in three forms:

- Repo skill: `.agents/skills/agentgate/SKILL.md`
- Codex app copy: `.codex/skills/agentgate/SKILL.md`
- Remote skill URL: `https://agentgate.fucito.it/skill/agentgate.md`
- GitHub ready skill with embedded public demo key: `github-ready-skill/agentgate/SKILL.md`

Local install:

```bash
./install-agentgate-skill.sh
export AGENTGATE_BASE_URL=https://agentgate.fucito.it
export AGENTGATE_API_KEY=ag_live_replace_me
```

Ready-to-use GitHub demo install:

```bash
./github-ready-skill/install-agentgate-skill.sh
```

This installs a Codex skill that already includes a public demo API key. The key is restricted server-side to the `web-demo` target and safe diagnostic commands, so judges can test AgentGate quickly without receiving SSH credentials or configuring environment variables.

Demo prompt:

```text
Usa AgentGate per diagnosticare il server hackrome-ssh: controlla utente, hostname, uptime e stato nginx.
```

GitHub ready skill prompt:

```text
Use AgentGate to check disk, memory, uptime, and processes on web-demo.
```

Docker install prompt:

```text
Usa AgentGate per installare Docker sul server hackrome-ssh se non e gia installato.
```

Example:

```bash
curl -sS -H "Authorization: Bearer $AGENTGATE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target":"web-demo","command":"df -h && free -m && uptime && ps aux | head"}' \
  http://localhost:8000/api/ssh/exec
```

## Security notes

- SSH credentials are encrypted with Fernet before storage.
- API keys are hashed for authentication. Exportable ready-skill keys are also stored encrypted so the dashboard can generate a complete Codex skill.
- Public GitHub demo keys are scoped server-side to safe targets and safe command patterns.
- Per-server command policy supports `allow_all` and `deny_all`.
- Deny patterns always win over allow patterns.
- This is a hackathon MVP, not an enterprise PAM replacement.

## Hackathon pitch

AI coding agents are becoming infrastructure operators. They can debug servers and fix production issues, but giving them SSH passwords or private keys is unsafe.

AgentGate is a cloud PAM broker for Codex skills. Developers onboard SSH targets once, generate an AgentGate API key, and Codex can operate through the broker. The agent never sees SSH credentials. Admins get a web dashboard, per-server command rules, and a complete audit trail.

In this MVP, Codex can diagnose a Linux server through AgentGate: disk, memory, uptime, services and logs. The integration is designed to be frictionless by default and progressively restrictable by policy.
