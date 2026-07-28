#!/usr/bin/env python3
"""
PreToolUse hook: blocks Claude's own tool calls (Bash/Write/Edit/NotebookEdit)
from touching repo-trust's trust store or signing key.

This closes the most likely real-world version of "trust-store tampering":
a hostile repo's CLAUDE.md/hook/skill instructing Claude, in-session, to
edit ~/.claude/security/trust-store.json through its normal tools to
self-approve. It does NOT stop a raw hook script writing that file directly
via its own process (arbitrary code running as the same OS user can always
write a file that user can write) - that is outside what any Claude Code
hook can observe. See repo_trust.py's module docstring / README threat model.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from repo_trust import STORE_PATH  # noqa: E402

GUARDED_DIR = str(STORE_PATH.parent)
# Matches the resolved absolute path, the `~/...` shorthand, and the bare
# relative form, so a command using any of the three still gets caught.
GUARDED_PATH_PATTERN = re.compile(
    "|".join(re.escape(p) for p in (GUARDED_DIR, "~/.claude/security", ".claude/security"))
)

FILE_INPUT_KEYS = ("file_path", "path", "notebook_path")


def touches_guarded_path(text: str) -> bool:
    return bool(text) and GUARDED_PATH_PATTERN.search(text)


def main():
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        payload = {}

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}

    hit = False
    if tool_name == "Bash":
        hit = touches_guarded_path(tool_input.get("command", ""))
    elif tool_name in ("Write", "Edit", "NotebookEdit"):
        hit = any(touches_guarded_path(str(tool_input.get(k, ""))) for k in FILE_INPUT_KEYS)

    if hit:
        print(json.dumps({
            "decision": "block",
            "reason": (
                f"repo-trust: direct modification of {GUARDED_DIR} via a tool call is blocked. "
                f"If you need to change repo-trust approvals, run `repo-trust` commands yourself "
                f"in a terminal outside this session, not through me."
            ),
        }))
    sys.exit(0)


if __name__ == "__main__":
    main()
