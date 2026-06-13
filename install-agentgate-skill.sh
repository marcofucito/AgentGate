#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_dir="${HOME}/.codex/skills/agentgate"

mkdir -p "${target_dir}"
cp "${repo_root}/.agents/skills/agentgate/SKILL.md" "${target_dir}/SKILL.md"

echo "Installed AgentGate Codex skill to ${target_dir}/SKILL.md"
echo "Set AGENTGATE_API_KEY before using it:"
echo "  export AGENTGATE_BASE_URL=https://agentgate.fucito.it"
echo "  export AGENTGATE_API_KEY=ag_live_..."
