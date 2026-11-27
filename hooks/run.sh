#!/bin/sh
# Launches the shellguard binary for the plugin's PreToolUse hook.
# Lookup order: $SHELLGUARD_BIN, PATH, $(go env GOBIN), ~/go/bin, ~/.local/bin.
# Without a binary every Bash call is escalated to a prompt (never waved through)
# with the install hint, until the binary is installed.
for c in "${SHELLGUARD_BIN:-}" "$(command -v shellguard 2>/dev/null)" \
         "${GOBIN:-}/shellguard" "$HOME/go/bin/shellguard" "$HOME/.local/bin/shellguard"; do
  if [ -n "$c" ] && [ -x "$c" ]; then
    exec "$c" hook
  fi
done
cat >/dev/null
printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"shellguard: the shellguard binary is not installed, so this command was not checked. Install it with: go install github.com/Cptweirdo/shellguard@latest"}}'
