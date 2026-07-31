#!/usr/bin/env python3
"""
PreToolUse hook: blocks Claude's own tool calls (Bash/Write/Edit/NotebookEdit)
from touching repo-trust's trust store, signing key, or (when running as a
plugin) the bundled org-trust-store and the plugin manifest that pins its
integrity hash.

This closes the most likely real-world version of "trust-store tampering":
a hostile repo's CLAUDE.md/hook/skill instructing Claude, in-session, to
edit ~/.claude/security/trust-store.json through its normal tools to
self-approve. It does NOT stop a raw hook script writing that file directly
via its own process (arbitrary code running as the same OS user can always
write a file that user can write) - that is outside what any Claude Code
hook can observe. See repo_trust.py's module docstring / README threat model.

The org-trust-store and plugin-manifest paths are guarded together and for
the same reason: editing the org list *and* the manifest's pinned hash
together through Claude's own tools would otherwise let a hostile repo
recompute a matching hash and defeat load_org_store()'s integrity check
entirely, not just tamper with one half of it.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from repo_trust import ORG_TRUST_STORE_PATH, PLUGIN_MANIFEST_PATH, STORE_PATH  # noqa: E402

# STORE_PATH's parent is safe to guard as a whole directory - it's a
# dedicated ~/.claude/security/ directory containing only repo-trust's own
# files. ORG_TRUST_STORE_PATH and PLUGIN_MANIFEST_PATH, by contrast, live
# inside the plugin/repo directory alongside ordinary project files (README,
# tests, etc.) - guarding *their* parent directories would block editing
# anything in the whole repo, not just these two files, so those two are
# guarded by exact path instead.
GUARDED_DIR = str(STORE_PATH.parent)
GUARDED_FILES = (str(ORG_TRUST_STORE_PATH), str(PLUGIN_MANIFEST_PATH))
# Matches the resolved absolute paths, the `~/...` shorthand, and the bare
# relative form, so a command using any of these still gets caught.
GUARDED_PATH_PATTERN = re.compile(
    "|".join(re.escape(p) for p in (GUARDED_DIR, "~/.claude/security", ".claude/security") + GUARDED_FILES)
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
                f"repo-trust: direct modification of {GUARDED_DIR} or repo-trust's org-trust-store/plugin manifest via a tool call is blocked. "
                f"If you need to change repo-trust approvals, run `repo-trust` commands yourself "
                f"in a terminal outside this session, not through me."
            ),
        }))
    sys.exit(0)


if __name__ == "__main__":
    main()
