#!/usr/bin/env python3
"""
UserPromptSubmit hook: the actual gate. Blocks turn processing for a repo
whose Claude configuration is unapproved or has drifted since approval.
Registered in ~/.claude/settings.json (user scope) so a hostile repo's own
project-level settings cannot suppress it (project settings can only add
hooks or disable ALL hooks via disableAllHooks - it cannot selectively
remove a single user-level hook).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import repo_trust  # noqa: E402
from repo_trust import check_status, repo_identity, find_repo_root, format_block_reason  # noqa: E402


def main():
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        payload = {}
    cwd = Path(payload.get("cwd", "."))
    root = find_repo_root(cwd)
    prompt = payload.get("prompt", "") or ""

    if prompt.strip().startswith("/claude-security"):
        repo_trust.record_security_scan(repo_identity(root))

    store = repo_trust.load_store()
    if not repo_trust.gate_enabled(store):
        sys.exit(0)

    result = check_status(cwd)
    if result["status"] == "trusted":
        sys.exit(0)

    print(json.dumps({"decision": "block", "reason": format_block_reason(result, root)}))
    sys.exit(0)


if __name__ == "__main__":
    main()
