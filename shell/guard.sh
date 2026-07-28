# repo-trust shell guard.
#
# Closes the "first SessionStart hook fires before repo-trust ever gets a
# turn" gap: Claude Code's own hook system cannot block that first launch
# (SessionStart has no blocking capability), so this gates the *launch of
# `claude` itself*, before Claude Code - and therefore any hook the target
# repo defines - ever starts.
#
# Install: add one line to your shell rc file (~/.zshrc or ~/.bashrc):
#
#   source /absolute/path/to/repo-trust/shell/guard.sh
#
# Then open a new shell. This only protects `claude` launched from a shell
# that has sourced this file - it does not cover the desktop app or IDE
# extensions launching Claude Code by other means.

claude() {
  if command -v repo-trust >/dev/null 2>&1; then
    repo-trust launch-check . || return 1
  fi
  command claude "$@"
}
