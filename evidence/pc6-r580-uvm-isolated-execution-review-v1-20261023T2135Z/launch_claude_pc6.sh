#!/usr/bin/env bash
set -euo pipefail
review_root=/home/pc6/claude-driver-hybrid-uvm-v5-20261023
agents_json="$(cat "$review_root/agents.json")"
cd "$review_root"
exec /home/pc6/.local/share/claude/versions/2.1.309 \
  --model claude-opus-5-5 \
  --effort max \
  --permission-mode acceptEdits \
  --plugin-dir /home/pc6/.claude/plugins/cache/claude-plugins-official/ralph-loop/1.0.0 \
  --agents "$agents_json" \
  --allowedTools Read Grep Glob Bash Write Agent
