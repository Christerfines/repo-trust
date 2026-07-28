# Changelog

## 0.2.0

**Fixed during pre-release review** (an independent pass over this same
release, not a later report — listed for the same reason `findingsAtApproval`
exists: so "this was checked and here's what it found" is answerable, not
just assumed):

- A file that's a symlink pointing *inside* the repo was no longer being
  read at all (an earlier draft of the inline symlink-escape check skipped
  reading through any symlink, escaping or not) — silently dropping it from
  both the content hash and pattern-matching. Fixed: only an escaping
  symlink's target goes unread now; an internal one is read and scanned as
  normal.
- The nested-CLAUDE.md walk's time cap only got checked once a candidate
  file was found in the current directory, so a large subtree with plenty
  of ordinary files and zero `CLAUDE.md`s (an unpruned `assets/`/`data/`
  tree, say) walked to completion with no time bound at all — the exact
  thing the cap exists to prevent, since this walk runs on every hook
  invocation. Fixed: elapsed time is checked once per directory regardless
  of what's in it.
- The "absolute path outside the repo" check compared the raw regex match
  against the repo root as a string, without resolving `..` first, so
  `/Users/<repo>/../../secret.pdf` read as "inside" by simple prefix
  matching even though it actually escapes. Fixed: the matched path is
  resolved before the containment check, same as every other call site.
- `check_status()` read `entry["configHash"]` with bracket access; a store
  entry missing that key (plausible from partial corruption, not just
  deliberate tampering) raised an uncaught `KeyError` instead of reporting
  `TAMPERED`/`DRIFTED` — a crashing hook is a worse failure mode than a
  loud one. Fixed to `.get()`, which now correctly falls through to
  `drifted`.
- `mutate_store()`'s fallback after exhausting every retry attempt saved a
  mutation computed against a stale version with no final re-check at all,
  silently overwriting whatever a concurrent writer had just landed —
  exactly the race the retry loop exists to prevent, defeated on its own
  worst-case path. Fixed to re-read once more before giving up, and to say
  so on stderr rather than clobbering silently.
- `install-hooks`/`uninstall-hooks` matched an existing hook entry purely
  by `command.endswith("hooks/<script>.py")`, which could also match an
  unrelated tool's own hook if it happened to share that relative path.
  Narrowed to also require the `python3 ` prefix repo-trust always
  generates — reduces, doesn't eliminate, the collision risk.
- README overclaimed that an `@import` token which "doesn't resolve" gets
  flagged; the actual (and intentional) behavior is to silently skip a
  token that doesn't resolve to any real file, since Claude Code wouldn't
  load one either — wording corrected to match.

**Breaking (intentional): the scanned surface widened.** repo-trust now also
scans `.claude/CLAUDE.md`, `CLAUDE.local.md`, `.claude/rules/`, every nested
`CLAUDE.md`/`CLAUDE.local.md` anywhere in the repo tree, and follows
`@path/to/file` imports inside CLAUDE.md-family files — all of these are
real Claude Code mechanisms that were previously untracked, meaning a
payload placed in one of them would pass `repo-trust review` clean and
never trigger drift detection. See [What gets scanned](README.md#what-gets-scanned)
for the full picture, including the documented performance-driven
pruning/caps on the new tree walk.

**Consequence of the above**: any repo you'd already approved that has
CLAUDE.md-family content will show `drifted` the next time it's checked,
because the tracked file set (and therefore the content hash) just grew.
This forces exactly one re-review under the wider scan — expected, not a
bug. Repos with only hooks/MCP config and no CLAUDE.md-family content are
unaffected structurally.

**Other changes:**

- Injection-phrasing detection (`INJECTION_PATTERNS`) now actually applies
  to every natural-language surface above, including nested/alternate
  CLAUDE.md locations and imported files — previously the fixed surface
  list meant several of these were hashed and drift-tracked but never
  pattern-matched.
- Symlink-escape detection is now inline in the same walk that reads file
  content, instead of a separate pass over a fixed path list, so a nested
  discovered file that's a symlink escape is no longer a blind spot. As a
  side effect, an escaping symlink's target is no longer read into the
  trust store's `perFileContent` cache at all — previously its bytes
  (which could be arbitrary local file content) were copied into
  `~/.claude/security/trust-store.json` even though the escape was
  flagged; now they simply aren't read.
- Approval signatures (`sigVersion: 2`) now cover the recorded findings and
  risk score, not just identity + content hash, so editing the audit trail
  outside `repo-trust review` is tamper-evident too. Legacy (`sigVersion: 1`)
  approvals keep verifying under the old scheme until they're next
  re-approved — upgrading never retroactively flags an untouched approval
  as `TAMPERED`. Signature comparison also switched to
  `hmac.compare_digest` (was a plain `!=`).
- Store writes use optimistic concurrency (`storeVersion` + retry-on-
  mismatch) instead of no protection at all, narrowing the lost-update
  window between near-simultaneous invocations (e.g. a CLI command and a
  hook's `/claude-security` timestamp write).
- New `repo-trust install-hooks` / `uninstall-hooks` commands register (or
  cleanly remove) the three hooks in `~/.claude/settings.json`, backing up
  the file first — replaces hand-editing JSON with the literal install
  path substituted in by hand.
- `pyproject.toml` added — `pip install .` works now, still zero runtime
  dependencies.
- Fixed an absolute-path boundary bug (`/repo` would also match `/repo2`)
  in both the symlink-escape check and the "absolute path outside the
  repo" pattern.

## 0.1.0

Initial release: trust-on-first-use gate for `.claude/settings*.json`,
`.mcp.json`, `CLAUDE.md`, `.claude/hooks`, `.claude/agents`,
`.claude/skills`, `.claude/commands`, `.claude-plugin`. Content-hash
approval with signed, drift-tracked entries; `SessionStart` / `UserPromptSubmit`
/ `PreToolUse` hooks; `shell/guard.sh` for closing the first-launch window.
