#!/usr/bin/env python3
"""
SessionStart hook: cannot block (Claude Code has no gate at this event), but
can inject context. Warns Claude/the user in-context if the repo it's
starting in is unapproved or has drifted since approval, so the model knows
to be cautious and to surface it rather than silently proceeding.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import repo_trust  # noqa: E402
from repo_trust import check_status, find_repo_root, format_block_reason  # noqa: E402


def emit(msg):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": msg}}))


def main():
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        payload = {}
    cwd = Path(payload.get("cwd", "."))
    root = find_repo_root(cwd)

    store = repo_trust.load_store()
    if not repo_trust.gate_enabled(store):
        sys.exit(0)

    result = check_status(cwd)
    status = result["status"]

    if status == "trusted":
        identity = result.get("identity")
        entry = store["repos"].get(identity)
        if entry and not entry.get("lastSecurityScanAt"):
            emit(
                "repo-trust: this repo's Claude configuration is approved, but it has never had a "
                "`/claude-security` deep code-security scan. Ask the user if they'd like you to run "
                "`/claude-security` now (repo-trust only checks whether Claude's config reaches outside "
                "the repo, not general code security)."
            )
        sys.exit(0)

    # This can't actually block the session (SessionStart has no blocking
    # capability) but reuses the same wording as the real block reason
    # (UserPromptSubmit / launch-check) since, with the gate enabled, that's
    # exactly what will happen the moment a turn is submitted.
    emit(format_block_reason(result, root))
    sys.exit(0)


if __name__ == "__main__":
    main()
