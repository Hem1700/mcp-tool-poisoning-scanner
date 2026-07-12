#!/usr/bin/env bash
set -euo pipefail
HOOK_DIR="$(git rev-parse --git-dir)/hooks"
cp "$(dirname "$0")/pre-push" "$HOOK_DIR/pre-push"
chmod +x "$HOOK_DIR/pre-push"
echo "Installed pre-push hook to $HOOK_DIR/pre-push"
