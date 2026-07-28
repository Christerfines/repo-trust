#!/usr/bin/env python3
"""
repo-trust: trust-on-first-use gate for a repo's Claude Code configuration.

Scans every surface Claude Code will read and execute for a repo:
.claude/settings*.json, .mcp.json, .claude/hooks, .claude/agents,
.claude/skills, .claude/commands, .claude/rules, .claude-plugin, plus the
full CLAUDE.md family - root CLAUDE.md, .claude/CLAUDE.md, CLAUDE.local.md,
and nested copies of either anywhere in the tree (Claude Code loads these
on demand as it reads files in a subdirectory) - and follows @import
references inside CLAUDE.md-family files. Flags anything that reaches
outside the repo (network calls, absolute/home paths, credential file
references, broad permission grants, external imports), and records a
human approval keyed to a content hash. If any tracked content changes,
the hash changes and the repo drops back to "unapproved" until re-reviewed.

This is a heuristic triage tool, not a substitute for reading the flagged
snippets yourself, and not a substitute for a real code-security scan
(Anthropic's own `/claude-security` plugin, run from inside an *already
approved* repo, covers that).

Known limitation: Claude Code's SessionStart hook cannot block a session,
so relying on hooks alone, a malicious repo's own SessionStart hook would
fire the very first time `claude` is launched inside it, before this tool
ever gets a turn. `shell/guard.sh` closes this for CLI launches by gating
`claude` itself (via `repo-trust launch-check`) before Claude Code ever
starts - see README. It does not cover non-CLI launches (desktop app, IDE
extensions), and it only helps if you've sourced it.

Known limitation: approvals are signed (see `sign_entry_v2`) to catch naive
tampering of ~/.claude/security/trust-store.json, but the signing key
lives at the same trust level as the store (same user, same file
permissions). This raises the bar against a generic rewrite; it is not a
cryptographic guarantee against an attacker who can also read the key
file. See README threat model.

Known limitation: the full-tree walk for nested CLAUDE.md-family files
prunes well-known dependency/build directories (see PRUNE_DIRS) and caps
total files/elapsed time for performance, since it runs on every hook
invocation. A nested CLAUDE.md placed inside a pruned directory, or a
repo large enough to hit the cap, is a documented, visible gap (the cap
surfaces as a WARN finding) rather than a silent one.
"""

import argparse
import difflib
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.2.0"

STORE_PATH = Path(
    os.environ.get("REPO_TRUST_STORE", str(Path.home() / ".claude" / "security" / "trust-store.json"))
)
KEY_PATH = Path(
    os.environ.get("REPO_TRUST_KEY", str(STORE_PATH.parent / "trust.key"))
)
SETTINGS_PATH = Path(
    os.environ.get("CLAUDE_SETTINGS_PATH", str(Path.home() / ".claude" / "settings.json"))
)

# Files/dirs read or executed by Claude Code, relative to a repo root.
CONFIG_FILES = [
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
    "CLAUDE.md",
    ".claude/CLAUDE.md",
    "CLAUDE.local.md",
]
CONFIG_DIRS = [
    ".claude/hooks",
    ".claude/agents",
    ".claude/skills",
    ".claude/commands",
    ".claude/rules",
    ".claude-plugin",
]

# Directories the full-tree nested-CLAUDE.md walk skips, for performance -
# these run on every hook invocation (SessionStart/UserPromptSubmit), so the
# walk has to be cheap by construction. A CLAUDE.md placed inside one of
# these is a documented, not a silent, gap - see module docstring.
PRUNE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".tox", "target", "vendor", ".terraform", "Pods", "coverage", ".next",
    ".idea", ".gradle",
}
MAX_WALK_FILES = 20000
MAX_WALK_SECONDS = 2.0
MAX_IMPORT_FOLLOWS = 50

CRITICAL_PATTERNS = [
    (r"\.ssh/(id_rsa|id_ed25519|id_ecdsa)\b", "reads an SSH private key"),
    (r"\.aws/credentials\b", "reads AWS credentials"),
    (r"\.netrc\b", "reads .netrc (stored credentials)"),
    (r"~/\.claude(-mem)?/(\.env|credentials|config\.json)\b", "reads Claude Code's own stored credentials"),
    (r"\b(ANTHROPIC|OPENAI)_API_KEY\b", "references an API key env var"),
    (r"/etc/passwd\b", "reads /etc/passwd"),
    (r"\bid_rsa\b|\bid_ed25519\b", "references a private key filename"),
]

WARN_PATTERNS = [
    (r"\bcurl\b|\bwget\b|\bnc\s+-|\bncat\b", "makes an outbound network call"),
    (r'"type"\s*:\s*"http"', "defines an HTTP hook (network call on every trigger)"),
    (r"\$HOME\b|~/(?!\.claude/(hooks|agents|skills|commands|rules))", "references a path outside the repo (home dir)"),
    (r'"Bash"\s*[,\]]|"Bash\(\*\*?\)"|"\*"\s*[,\]]', "grants a broad/unscoped permission"),
    (r"\beval\b|\bexec\(|os\.system\(|shell\s*=\s*True", "uses dynamic code execution"),
    (r"\bbase64\s+(-d|--decode)\b", "decodes base64 (common obfuscation for hook payloads)"),
    (r"\bnpx\s+(-y|--yes)\b", "runs a package via npx without review (auto-confirms install)"),
    (r"\bpipx?\s+(install|run)\b", "installs/runs a Python package at runtime"),
    (r"(?:\\x[0-9a-fA-F]{2}){9,}", "contains a long hex-escaped byte string (possible obfuscated payload)"),
    (r"\batob\(|Buffer\.from\([^)]*['\"]base64", "decodes base64 (JS)"),
    (r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", "PowerShell encoded-command (common obfuscation)"),
    (r"\bpython3?\s+-c\s+['\"]", "runs an inline python one-liner"),
]

# Checked separately from WARN_PATTERNS because it needs the repo root to tell
# "absolute path pointing at this repo" (fine - e.g. an auto-recorded
# `Bash(git -C /repo/root ...)` permission rule) apart from "absolute path
# pointing somewhere else" (worth flagging).
ABS_PATH_PATTERN = r"(?<![\w/.])/(?:Users|home)/[\w.\-/]+"

INFO_PATTERNS = [
    (r'"hooks"\s*:', "defines hooks"),
    (r'"mcpServers"\s*:', "defines MCP servers"),
]

# Applied to natural-language instruction surfaces (the CLAUDE.md family,
# .claude/skills, .claude/agents, .claude/commands, .claude/rules, and any
# file reached via @import from a CLAUDE.md-family file) - not hook scripts
# or JSON, to keep the false-positive rate down.
INJECTION_PATTERNS = [
    (r"ignore (all |any )?(previous|prior|above|earlier) instructions", "phrasing resembles a prompt-injection instruction (heuristic - verify by reading context)"),
    (r"disregard (the )?(above|previous|prior)", "phrasing resembles a prompt-injection instruction (heuristic - verify by reading context)"),
    (r"do not (tell|inform|mention|show) (this|it|the user)", "phrasing resembles an instruction to hide actions from the user (heuristic - verify by reading context)"),
    (r"without (asking|telling|notifying) the user", "phrasing resembles an instruction to bypass user awareness (heuristic - verify by reading context)"),
    (r"send (this|the|your) (file|contents?|key|credentials?|ssh key|env(ironment)?) to", "phrasing resembles an exfiltration instruction (heuristic - verify by reading context)"),
    (r"\bexfiltrate\b", "mentions exfiltration explicitly (heuristic - verify by reading context)"),
]

NL_SURFACE_DIRS = (".claude/skills", ".claude/agents", ".claude/commands", ".claude/rules")
CLAUDE_MD_BASENAMES = ("claude.md", "claude.local.md")


def is_claude_md_family(rel: str) -> bool:
    return Path(rel).name.lower() in CLAUDE_MD_BASENAMES


def is_nl_surface(rel: str) -> bool:
    if is_claude_md_family(rel):
        return True
    return rel.startswith(NL_SURFACE_DIRS)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def repo_identity(path: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(path), "config", "--get", "remote.origin.url"],
            capture_output=True, text=True, timeout=5,
        )
        url = out.stdout.strip()
        if url:
            return url
    except Exception:
        pass
    return str(path.resolve())


def find_repo_root(path: Path) -> Path:
    """Resolve to the git top-level of `path` if it's inside a git repo, else `path` unchanged."""
    try:
        out = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        top = out.stdout.strip()
        if out.returncode == 0 and top:
            return Path(top).resolve()
    except Exception:
        pass
    return path.resolve()


def _inside(candidate: Path, root_resolved: Path) -> bool:
    candidate = str(candidate)
    root_s = str(root_resolved)
    return candidate == root_s or candidate.startswith(root_s + os.sep)


def collect_files(root: Path):
    """Return ({relpath: bytes}, [structural findings]) for the fixed config
    surface plus every nested CLAUDE.md/CLAUDE.local.md found anywhere in the
    tree (pruned/capped - see PRUNE_DIRS/MAX_WALK_*). Structural findings are
    symlink-escape detections and a truncation warning, discovered inline
    during the same walk that reads content - not a separate pass.
    """
    root_resolved = root.resolve()
    files = {}
    findings = []

    def read_or_flag(p: Path, rel: str):
        if p.is_symlink():
            target = p.resolve()
            if not _inside(target, root_resolved):
                findings.append({
                    "file": rel, "severity": "CRITICAL", "line": 1,
                    "message": f"config path is a symlink pointing outside the repo (-> {target})",
                    "snippet": f"{rel} -> {target}",
                })
                return  # never read an escaping symlink's target
            if target.is_file():
                try:
                    files[rel] = target.read_bytes()
                except OSError:
                    pass
            return
        if p.is_file():
            try:
                files[rel] = p.read_bytes()
            except OSError:
                pass

    for rel in CONFIG_FILES:
        p = root / rel
        if p.exists() or p.is_symlink():
            read_or_flag(p, rel)

    handled_dirs = set()
    for reldir in CONFIG_DIRS:
        base = root / reldir
        handled_dirs.add(base.resolve())
        if base.is_symlink():
            read_or_flag(base, reldir)
            continue
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            for dn in list(dirnames):
                dp = Path(dirpath) / dn
                if dp.is_symlink():
                    read_or_flag(dp, str(dp.relative_to(root)))
                    dirnames.remove(dn)
            for fn in filenames:
                p = Path(dirpath) / fn
                read_or_flag(p, str(p.relative_to(root)))

    start = time.monotonic()
    file_count = 0
    truncated = False
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if (time.monotonic() - start) > MAX_WALK_SECONDS:
            # Checked once per directory regardless of whether it contains a
            # candidate file - a huge unpruned subtree with zero CLAUDE.md
            # files would otherwise walk to completion with no time bound.
            truncated = True
            break
        dp = Path(dirpath)
        for dn in list(dirnames):
            child = dp / dn
            if dn in PRUNE_DIRS or child.resolve() in handled_dirs:
                dirnames.remove(dn)
                continue
            if child.is_symlink():
                target = child.resolve()
                if not _inside(target, root_resolved):
                    findings.append({
                        "file": str(child.relative_to(root)), "severity": "CRITICAL", "line": 1,
                        "message": f"config path is a symlink pointing outside the repo (-> {target})",
                        "snippet": f"{child.relative_to(root)} -> {target}",
                    })
                dirnames.remove(dn)  # never descend into a symlinked dir
        for fn in filenames:
            if fn.lower() not in CLAUDE_MD_BASENAMES:
                continue
            file_count += 1
            if file_count > MAX_WALK_FILES or (time.monotonic() - start) > MAX_WALK_SECONDS:
                truncated = True
                break
            p = dp / fn
            rel = str(p.relative_to(root))
            if rel in files:
                continue
            read_or_flag(p, rel)
        if truncated:
            break

    if truncated:
        findings.append({
            "file": ".", "severity": "WARN", "line": 0,
            "message": "tree walk truncated for performance - repo may be larger than repo-trust can fully verify; review manually",
            "snippet": f"stopped after {file_count} candidate files / {MAX_WALK_SECONDS}s",
        })

    return files, findings


FENCE_RE = re.compile(r"^\s*```")
INLINE_CODE_RE = re.compile(r"`[^`\n]*`")
IMPORT_TOKEN_RE = re.compile(r"(?<!\w)@(~[\w./~-]*|/[\w./~-]*|[\w.][\w./~-]*)")


def mask_code_for_imports(text: str):
    """Blank out fenced code blocks and inline code spans (same length, so
    line/offset numbers stay accurate) before import-token scanning, mirroring
    Claude Code's own import parser skipping code spans/fences. An unclosed
    trailing fence is deliberately left un-blanked (scanned, not excluded) and
    flagged - failing toward detection rather than away from it.
    """
    lines = text.split("\n")
    masked = list(lines)
    in_fence = False
    fence_start = None
    for i, line in enumerate(lines):
        if FENCE_RE.match(line):
            if not in_fence:
                in_fence = True
                fence_start = i
            else:
                for j in range(fence_start, i + 1):
                    masked[j] = " " * len(lines[j])
                in_fence = False
                fence_start = None
    unclosed_line = fence_start + 1 if in_fence else None
    for i, line in enumerate(masked):
        if line != lines[i]:
            continue  # already blanked as part of a closed fence
        masked[i] = INLINE_CODE_RE.sub(lambda m: " " * len(m.group(0)), line)
    return "\n".join(masked), unclosed_line


def _resolve_import_token(importing_file: Path, token: str):
    try:
        if token.startswith("~"):
            candidate = Path(os.path.expanduser(token))
        elif token.startswith("/"):
            candidate = Path(token)
        else:
            candidate = importing_file.parent / token
        return candidate.resolve()
    except OSError:
        return None


def resolve_imports(root: Path, files: dict):
    """Follow @import references from CLAUDE.md-family files, merging
    in-repo targets into `files` (so they're hashed/drift-tracked/analyzed
    like any other tracked file) and flagging out-of-repo targets. Returns
    (imported_rels, findings) - imported_rels lets analyze() treat imported
    content as an NL surface (injection patterns apply) even if its own path
    wouldn't otherwise qualify.
    """
    root_resolved = root.resolve()
    findings = []
    imported_rels = set()
    visited = set()
    queue = [rel for rel in list(files) if is_claude_md_family(rel)]
    seen_queue = set(queue)

    while queue:
        rel = queue.pop()
        content = files.get(rel)
        if content is None:
            continue
        text = content.decode("utf-8", errors="replace")
        masked, unclosed_line = mask_code_for_imports(text)
        if unclosed_line is not None:
            findings.append({
                "file": rel, "severity": "WARN", "line": unclosed_line,
                "message": "unclosed code fence - contents after it are still scanned for imports, but the malformed fence itself is worth inspecting",
                "snippet": text.splitlines()[unclosed_line - 1].strip()[:120],
            })

        importing_file = root / rel
        for m in IMPORT_TOKEN_RE.finditer(masked):
            if len(visited) >= MAX_IMPORT_FOLLOWS:
                break
            token = m.group(1)
            resolved = _resolve_import_token(importing_file, token)
            if resolved is None or not resolved.is_file():
                continue
            key = str(resolved)
            if key in visited:
                continue
            visited.add(key)

            line_no = text.count("\n", 0, m.start()) + 1
            if _inside(resolved, root_resolved):
                new_rel = str(resolved.relative_to(root_resolved))
                imported_rels.add(new_rel)
                if new_rel not in files:
                    try:
                        files[new_rel] = resolved.read_bytes()
                    except OSError:
                        continue
                if new_rel != rel and new_rel not in seen_queue:
                    queue.append(new_rel)
                    seen_queue.add(new_rel)
            else:
                findings.append({
                    "file": rel, "severity": "WARN", "line": line_no,
                    "message": "imports a file outside the repo - Claude Code gates this with its own approval dialog, but repo-trust cannot see its contents; inspect manually",
                    "snippet": text.splitlines()[line_no - 1].strip()[:120],
                })

    return imported_rels, findings


def gather(root: Path):
    """Everything Claude Code would read for this repo, plus every finding
    the discovery process itself produced. Returns (files, findings, imported_rels).
    """
    files, findings = collect_files(root)
    imported_rels, import_findings = resolve_imports(root, files)
    return files, findings + import_findings, imported_rels


def compute_hash(files: dict) -> tuple:
    """Returns (combined_hash, {relpath: filehash})."""
    per_file = {rel: sha256_bytes(content) for rel, content in files.items()}
    manifest = "\n".join(f"{rel}:{len(files[rel])}:{per_file[rel]}" for rel in sorted(per_file))
    return sha256_bytes(manifest.encode()), per_file


def analyze(files: dict, root: Path, imported_rels=frozenset()):
    """Returns list of {file, severity, message, snippet} - pattern-based
    findings only. Structural findings (symlink escapes, truncation, external
    imports) come from collect_files()/resolve_imports() via gather().
    """
    findings = []
    root_resolved = str(root.resolve())
    for rel, content in files.items():
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            continue

        def add(severity, message, m):
            line_no = text.count("\n", 0, m.start()) + 1
            snippet = text.splitlines()[line_no - 1].strip()[:120]
            findings.append({"file": rel, "severity": severity, "message": message, "line": line_no, "snippet": snippet})

        for severity, patterns in (("CRITICAL", CRITICAL_PATTERNS), ("WARN", WARN_PATTERNS), ("INFO", INFO_PATTERNS)):
            for pattern, message in patterns:
                m = re.search(pattern, text)
                if m:
                    add(severity, message, m)

        if is_nl_surface(rel) or rel in imported_rels:
            for pattern, message in INJECTION_PATTERNS:
                m = re.search(pattern, text, re.IGNORECASE)
                if m:
                    add("WARN", message, m)

        for m in re.finditer(ABS_PATH_PATTERN, text):
            try:
                resolved = Path(m.group(0)).resolve()
            except OSError:
                resolved = Path(m.group(0))
            if not _inside(resolved, Path(root_resolved)):
                add("WARN", "references an absolute filesystem path outside the repo", m)

    return findings


def sort_findings(findings):
    order = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
    return sorted(findings, key=lambda f: (order[f["severity"]], f["file"], f["line"]))


SEVERITY_WEIGHT = {"CRITICAL": 4, "WARN": 1, "INFO": 0}
SEVERITY_COLOR = {"CRITICAL": "\033[31m", "WARN": "\033[33m", "INFO": "\033[36m"}
COLOR_RESET = "\033[0m"


def risk_score(findings) -> tuple:
    """Returns (score 0-10, label)."""
    score = min(10, sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))
    if score == 0:
        label = "CLEAN"
    elif score <= 3:
        label = "LOW"
    elif score <= 6:
        label = "MEDIUM"
    else:
        label = "HIGH"
    return score, label


def use_color() -> bool:
    try:
        isatty = sys.stdout.isatty()
    except Exception:
        isatty = False
    return isatty and not os.environ.get("NO_COLOR")


def load_store() -> dict:
    if STORE_PATH.is_file():
        try:
            return json.loads(STORE_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"repos": {}}


def save_store(store: dict):
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(store, indent=2, sort_keys=True))
    tmp.replace(STORE_PATH)
    try:
        STORE_PATH.chmod(0o600)
    except OSError:
        pass


def mutate_store(mutate_fn, attempts=5):
    """Load, apply mutate_fn(store) -> store, and save with an optimistic-
    concurrency retry instead of a blocking lock. The real concurrent-write
    surface here is small (a CLI command and a hook's record_security_scan
    landing at nearly the same instant) and low-severity (worst case: one
    write is lost, not a security bypass) - a lockfile-with-timeout would, on
    timeout, fall back to writing unprotected anyway, reproducing the exact
    race it exists to prevent. This never blocks, so it can't itself cause a
    hook to time out. It narrows the race, not closes it: there's still a
    small window between the final version check and the write, since
    stdlib offers no portable atomic compare-and-swap on file content. See
    README threat model.
    """
    for attempt in range(attempts):
        store = load_store()
        seen_version = store.get("storeVersion", 0)
        result = mutate_fn(store)
        result["storeVersion"] = seen_version + 1
        if load_store().get("storeVersion", 0) != seen_version:
            time.sleep(0.02 * (attempt + 1))
            continue
        save_store(result)
        return result
    # Persistent contention across every attempt: apply the mutation on top
    # of the latest state we can see rather than a stale one, but this last
    # write is not itself version-checked - say so loudly instead of
    # silently overwriting whatever a concurrent writer just landed.
    store = load_store()
    result = mutate_fn(store)
    result["storeVersion"] = store.get("storeVersion", 0) + 1
    print(
        f"repo-trust: store write proceeded after {attempts} contended attempts; "
        "a concurrent write may have been overwritten.",
        file=sys.stderr,
    )
    save_store(result)
    return result


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_or_create_signing_key() -> bytes:
    """Local HMAC key used to sign approval entries against naive tampering.

    This lives at the same trust level as the store itself (same user, same
    permissions) - it raises the bar against a generic/naive rewrite of the
    store, it is not a defense against an attacker who can also read this
    file. See README threat model.
    """
    if KEY_PATH.is_file():
        try:
            return bytes.fromhex(KEY_PATH.read_text().strip())
        except (OSError, ValueError):
            pass
    key = os.urandom(32)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEY_PATH.write_text(key.hex())
    try:
        KEY_PATH.chmod(0o600)
    except OSError:
        pass
    return key


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def sign_entry_v1(identity: str, config_hash: str) -> str:
    """Legacy (pre-0.2.0) signing scheme - identity+hash only. Kept for
    verifying entries approved before findings/riskScore were covered by the
    signature; never used to sign new approvals."""
    key = get_or_create_signing_key()
    return hmac.new(key, f"{identity}:{config_hash}".encode(), hashlib.sha256).hexdigest()


def sign_entry_v2(identity: str, config_hash: str, findings: list, risk: dict, approved_at: str) -> str:
    """Current signing scheme - covers the full audit record (findings and
    risk score at approval time, not just identity+hash) so editing those
    fields outside `repo-trust review` is tamper-evident too."""
    key = get_or_create_signing_key()
    payload = canonical_json({
        "identity": identity,
        "configHash": config_hash,
        "findingsAtApproval": findings,
        "riskScoreAtApproval": risk,
        "approvedAt": approved_at,
    })
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def verify_entry(entry: dict, identity: str, config_hash: str) -> bool:
    """Dispatches on the entry's declared sigVersion so a signing-scheme
    change never retroactively flags an untouched legacy approval as
    TAMPERED - only entries that actually fail verification under their own
    declared scheme are tampered."""
    version = entry.get("sigVersion", 1)
    if version == 2:
        expected = sign_entry_v2(
            identity, config_hash,
            entry.get("findingsAtApproval", []),
            entry.get("riskScoreAtApproval", {}),
            entry.get("approvedAt", ""),
        )
    else:
        expected = sign_entry_v1(identity, config_hash)
    return hmac.compare_digest(entry.get("signature", ""), expected)


def gate_enabled(store: dict) -> bool:
    return store.get("gateEnabled", True)


def set_gate_enabled(enabled: bool):
    def mutate(store):
        store["gateEnabled"] = enabled
        return store
    mutate_store(mutate)


def record_security_scan(identity: str):
    def mutate(store):
        entry = store["repos"].setdefault(identity, {"path": identity})
        entry["lastSecurityScanAt"] = now_iso()
        return store
    mutate_store(mutate)


def diff_changed_files(entry: dict, files: dict, changed: list) -> dict:
    """Returns {rel: diff_text} for changed files, using stored content if available."""
    old_content = entry.get("perFileContent", {})
    diffs = {}
    for rel in changed:
        old_text = old_content.get(rel)
        if old_text is None:
            diffs[rel] = "(no stored content to diff - approved before diff tracking was added; re-approve to enable)"
            continue
        new_text = files.get(rel, b"").decode("utf-8", errors="replace") if rel in files else ""
        lines = list(difflib.unified_diff(
            old_text.splitlines(), new_text.splitlines(),
            fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="", n=3,
        ))
        diffs[rel] = "\n".join(lines[:15]) if lines else "(no textual difference)"
    return diffs


def check_status(path: Path) -> dict:
    """Core gate check used by hooks. Returns dict with status + details."""
    path = find_repo_root(path)
    files, _findings, _imported = gather(path)
    if not files:
        return {"status": "trusted", "reason": "no .claude/MCP configuration present", "identity": repo_identity(path)}

    combined_hash, per_file = compute_hash(files)
    identity = repo_identity(path)
    store = load_store()
    entry = store["repos"].get(identity)

    if entry is None:
        return {"status": "unapproved", "identity": identity, "hash": combined_hash}

    if entry.get("configHash") != combined_hash:
        old_files = entry.get("perFileHash", {})
        changed = sorted(
            rel for rel in set(old_files) | set(per_file)
            if old_files.get(rel) != per_file.get(rel)
        )
        diffs = diff_changed_files(entry, files, changed)
        return {"status": "drifted", "identity": identity, "hash": combined_hash, "changed_files": changed, "diffs": diffs}

    if not verify_entry(entry, identity, combined_hash):
        return {"status": "tampered", "identity": identity, "hash": combined_hash}

    return {"status": "trusted", "identity": identity, "hash": combined_hash, "approvedAt": entry.get("approvedAt")}


def format_block_reason(result: dict, path) -> str:
    """Shared block-message text for hooks and `launch-check`."""
    status = result["status"]
    if status == "unapproved":
        reason = (
            f"Blocked by repo-trust: {result.get('identity')} has not been reviewed. "
            f"Run `repo-trust review {path}` in a plain terminal (not through me) to see what its "
            f".claude/ configuration would reach outside the repo, then approve or decline."
        )
    elif status == "drifted":
        changed = ", ".join(result.get("changed_files", [])) or "unknown files"
        reason = (
            f"Blocked by repo-trust: {result.get('identity')}'s Claude configuration changed since "
            f"approval ({changed}). Run `repo-trust review {path}` to review the change and re-approve."
        )
    else:  # tampered
        reason = (
            f"Blocked by repo-trust: {result.get('identity')}'s approval record does not match its "
            f"signature - it may have been modified outside `repo-trust review`. Treat as compromised. "
            f"Inspect manually, then `repo-trust forget {path}` and re-review."
        )
    return reason + "\n\nTo turn this gate off entirely: `repo-trust disable` (re-enable with `repo-trust enable`)."


def print_findings(findings):
    if not findings:
        print("No risk signals matched the heuristics. Read .claude/ yourself before trusting this blindly.")
        return
    color = use_color()
    for f in findings:
        tag = f"[{f['severity']:8}]"
        if color:
            tag = f"{SEVERITY_COLOR[f['severity']]}{tag}{COLOR_RESET}"
        print(f"  {tag} {f['file']}:{f['line']}  {f['message']}")
        print(f"             {f['snippet']}")


def print_risk_score(findings):
    score, label = risk_score(findings)
    color = use_color()
    severity_for_label = {"CLEAN": "INFO", "LOW": "INFO", "MEDIUM": "WARN", "HIGH": "CRITICAL"}
    line = f"Risk: {score}/10 - {label}"
    if color:
        line = f"{SEVERITY_COLOR[severity_for_label[label]]}{line}{COLOR_RESET}"
    print(line)


def cmd_review(args):
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1
    root = find_repo_root(root)

    identity = repo_identity(root)
    print(f"Repo:     {root}")
    print(f"Identity: {identity}")

    files, pre_findings, imported_rels = gather(root)
    findings = []
    if not files:
        print("No .claude/ or MCP configuration found - nothing for Claude Code to reach outside the repo with.")
        combined_hash, per_file = "", {}
    else:
        combined_hash, per_file = compute_hash(files)
        print(f"Files scanned ({len(files)}):")
        for rel in sorted(files):
            print(f"  - {rel}")
        print()
        findings = sort_findings(pre_findings + analyze(files, root, imported_rels))
        print("Findings:")
        print_findings(findings)
        print()
        print_risk_score(findings)

    print()
    print("This checks 'does this reach outside the repo', not general code quality.")
    print("For a deeper code-level scan, once you trust this repo enough to open it,")
    print("run `/claude-security` inside the Claude Code session.")
    print()

    if args.yes:
        approve = True
    else:
        resp = input("Approve this repo's Claude configuration? [y/N] ").strip().lower()
        approve = resp in ("y", "yes")

    if not approve:
        print("Not approved.")
        return 1

    score, label = risk_score(findings)
    approved_at = now_iso()
    signature = sign_entry_v2(identity, combined_hash, findings, {"score": score, "label": label}, approved_at)

    def mutate(store):
        prior = store["repos"].get(identity, {})
        store["repos"][identity] = {
            "path": str(root),
            "configHash": combined_hash,
            "perFileHash": per_file,
            "perFileContent": {rel: content.decode("utf-8", errors="replace") for rel, content in files.items()},
            "signature": signature,
            "sigVersion": 2,
            "approvedAt": approved_at,
            "lastSecurityScanAt": prior.get("lastSecurityScanAt"),
            "findingsAtApproval": findings,
            "riskScoreAtApproval": {"score": score, "label": label},
        }
        return store

    mutate_store(mutate)
    print(f"Approved and recorded ({STORE_PATH}).")
    return 0


def cmd_status(args):
    root = find_repo_root(Path(args.path).resolve())
    result = check_status(root)
    if args.json:
        print(json.dumps(result))
    else:
        print(f"{result['status'].upper()}: {result.get('identity', root)}")
        if result["status"] == "drifted":
            print("Changed since approval:")
            for rel in result["changed_files"]:
                print(f"  - {rel}")
                diff = result.get("diffs", {}).get(rel)
                if diff:
                    for line in diff.splitlines():
                        print(f"    {line}")
        elif result["status"] == "tampered":
            print(format_block_reason(result, root))
        store = load_store()
        entry = store["repos"].get(result.get("identity"))
        scan = entry.get("lastSecurityScanAt") if entry else None
        print(f"Gate:          {'ENABLED' if gate_enabled(store) else 'DISABLED'}")
        print(f"Security scan: {scan or 'never'}")
        if result["status"] == "trusted" and entry and entry.get("riskScoreAtApproval"):
            r = entry["riskScoreAtApproval"]
            n = len(entry.get("findingsAtApproval", []))
            print(f"Approved at risk {r['score']}/10 ({r['label']}) with {n} finding(s).")
    return 0 if result["status"] == "trusted" else 1


def cmd_launch_check(args):
    """Used by shell/guard.sh to decide whether to exec the real `claude` binary at all."""
    root = find_repo_root(Path(args.path).resolve())
    store = load_store()
    if not gate_enabled(store):
        return 0
    result = check_status(root)
    if result["status"] == "trusted":
        return 0
    print(format_block_reason(result, root), file=sys.stderr)
    return 1


def cmd_list(args):
    store = load_store()
    print(f"Gate: {'ENABLED' if gate_enabled(store) else 'DISABLED'}")
    if not store["repos"]:
        print("No approved repos yet.")
        return 0
    for identity, entry in sorted(store["repos"].items()):
        scan = entry.get("lastSecurityScanAt") or "never"
        print(f"{entry.get('approvedAt', '?')}  {identity}  ({entry.get('path', '?')})  security-scan={scan}")
    return 0


def cmd_enable(args):
    set_gate_enabled(True)
    print("repo-trust gate ENABLED. Unapproved/drifted repos will block turns again.")
    return 0


def cmd_disable(args):
    set_gate_enabled(False)
    print("repo-trust gate DISABLED. Unapproved/drifted repos will NOT be blocked until you run `repo-trust enable`.")
    return 0


def cmd_forget(args):
    root = find_repo_root(Path(args.path).resolve())
    identity = repo_identity(root)
    outcome = {"removed": None}

    def mutate(store):
        if identity in store["repos"]:
            del store["repos"][identity]
            outcome["removed"] = identity
        elif args.path in store["repos"]:
            del store["repos"][args.path]
            outcome["removed"] = args.path
        return store

    mutate_store(mutate)
    if outcome["removed"]:
        print(f"Removed approval for {outcome['removed']}.")
        return 0
    print(f"No stored approval for {identity}.", file=sys.stderr)
    return 1


# --- hook installation -------------------------------------------------

HOOK_SCRIPTS = {
    "SessionStart": "session_start.py",
    "UserPromptSubmit": "user_prompt_submit.py",
    "PreToolUse": "pre_tool_use.py",
}
HOOK_TIMEOUT_SECONDS = 10


def _repo_trust_root() -> Path:
    return Path(__file__).resolve().parent


def _hook_command(script_name: str) -> str:
    return f"python3 {_repo_trust_root() / 'hooks' / script_name}"


def _is_our_hook_command(command: str, script_name: str) -> bool:
    """Matches the exact shape repo-trust generates (`python3 <path>/hooks/<script>`),
    not just an arbitrary command that happens to end in the same filename -
    narrows, though doesn't eliminate, collision with an unrelated tool whose
    own hook script happens to share that relative path."""
    return command.startswith("python3 ") and command.endswith(f"hooks/{script_name}")


def _load_settings() -> dict:
    if SETTINGS_PATH.is_file():
        try:
            return json.loads(SETTINGS_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_settings(settings: dict):
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SETTINGS_PATH.is_file():
        backup = SETTINGS_PATH.with_name(SETTINGS_PATH.name + f".bak-{now_iso().replace(':', '')}")
        backup.write_text(SETTINGS_PATH.read_text())
    SETTINGS_PATH.write_text(json.dumps(settings, indent=2, sort_keys=True) + "\n")


def cmd_install_hooks(args):
    settings = _load_settings()
    hooks = settings.setdefault("hooks", {})
    summary = []
    for event, script_name in HOOK_SCRIPTS.items():
        command = _hook_command(script_name)
        groups = hooks.setdefault(event, [])
        found = False
        updated = False
        for group in groups:
            for h in group.get("hooks", []):
                if h.get("type") == "command" and _is_our_hook_command(h.get("command", ""), script_name):
                    found = True
                    if h.get("command") != command:
                        h["command"] = command
                        h["timeout"] = HOOK_TIMEOUT_SECONDS
                        updated = True
        if not found:
            groups.append({"hooks": [{"type": "command", "command": command, "timeout": HOOK_TIMEOUT_SECONDS}]})
            summary.append(f"{event}: added")
        elif updated:
            summary.append(f"{event}: path updated")
        else:
            summary.append(f"{event}: already installed")
    _save_settings(settings)
    for line in summary:
        print(line)
    print(f"Hooks configured in {SETTINGS_PATH}")
    return 0


def cmd_uninstall_hooks(args):
    settings = _load_settings()
    hooks = settings.get("hooks", {})
    summary = []
    for event, script_name in HOOK_SCRIPTS.items():
        groups = hooks.get(event, [])
        new_groups = []
        removed = False
        for group in groups:
            kept = [h for h in group.get("hooks", []) if not _is_our_hook_command(h.get("command", ""), script_name)]
            if len(kept) != len(group.get("hooks", [])):
                removed = True
            if kept:
                new_groups.append({**group, "hooks": kept})
        hooks[event] = new_groups
        summary.append(f"{event}: {'removed' if removed else 'not present'}")
    settings["hooks"] = hooks
    _save_settings(settings)
    for line in summary:
        print(line)
    print(f"Hooks removed from {SETTINGS_PATH}")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="repo-trust", description=__doc__.strip().splitlines()[0])
    parser.add_argument("--version", action="version", version=f"repo-trust {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_review = sub.add_parser("review", help="scan a repo's Claude config, summarize, and record approval")
    p_review.add_argument("path", nargs="?", default=".")
    p_review.add_argument("--yes", action="store_true", help="skip the interactive prompt and approve")
    p_review.set_defaults(func=cmd_review)

    p_status = sub.add_parser("status", help="check trusted/drifted/unapproved for a repo")
    p_status.add_argument("path", nargs="?", default=".")
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=cmd_status)

    p_list = sub.add_parser("list", help="list all approved repos")
    p_list.set_defaults(func=cmd_list)

    p_forget = sub.add_parser("forget", help="revoke approval for a repo")
    p_forget.add_argument("path")
    p_forget.set_defaults(func=cmd_forget)

    p_enable = sub.add_parser("enable", help="turn the repo-trust gate back on (global)")
    p_enable.set_defaults(func=cmd_enable)

    p_disable = sub.add_parser("disable", help="turn the repo-trust gate off (global) - stops all blocking")
    p_disable.set_defaults(func=cmd_disable)

    p_launch = sub.add_parser("launch-check", help="used by shell/guard.sh - exit 0 if `claude` should be allowed to launch here")
    p_launch.add_argument("path", nargs="?", default=".")
    p_launch.set_defaults(func=cmd_launch_check)

    p_install = sub.add_parser("install-hooks", help="register repo-trust's hooks in ~/.claude/settings.json")
    p_install.set_defaults(func=cmd_install_hooks)

    p_uninstall = sub.add_parser("uninstall-hooks", help="remove repo-trust's hooks from ~/.claude/settings.json")
    p_uninstall.set_defaults(func=cmd_uninstall_hooks)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
