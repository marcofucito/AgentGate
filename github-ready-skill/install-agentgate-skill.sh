#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_dir="${HOME}/.codex/skills/agentgate"

mkdir -p "${target_dir}"
cp "${script_dir}/agentgate/SKILL.md" "${target_dir}/SKILL.md"
chmod 600 "${target_dir}/SKILL.md"

echo "Installed ready-to-use AgentGate Codex skill:"
echo "  ${target_dir}/SKILL.md"
echo
echo "The public demo API key is already embedded and scoped to safe web-demo diagnostics."
echo "Try asking Codex:"
echo "  Use AgentGate to check disk, memory, uptime, and processes on web-demo."
