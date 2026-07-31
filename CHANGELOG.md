# Changelog

## 0.3.0

**Company-wide deployment.** repo-trust now ships as a Claude Code plugin
(`.claude-plugin/plugin.json`, `hooks/hooks.json`) so an organization can
force-enable it via `managed-settings.json`'s `enabledPlugins` +
`allowManagedHooksOnly: true`, guaranteeing every developer runs it without
relying on each of them individually running `install-hooks`. A plugin can
also bundle a read-only `org-trust-store.json` so a security team can
pre-approve common internal repos once instead of every developer
re-reviewing the same ones separately. New `repo-trust mode` diagnoses
whether managed-hooks-only mode looks active on a given machine.

This is additive: nothing about the existing single-developer flow
(`install-hooks`, a personal trust store, `repo-trust review`) changes for
anyone not using the plugin/managed-settings path.

Two real bypasses were found and fixed during design review, before either
shipped:
- An org-approved entry now requires the **same content-hash equality** a
  personal approval does — matching on identity alone (`git remote add
  origin <url-of-a-vetted-repo>` on a malicious clone) would otherwise have
  inherited automatic trust regardless of actual content. An org entry only
  skips the human-approval step, never the drift check.
- The bundled `org-trust-store.json`'s integrity is verified against a hash
  pinned into `plugin.json` (`repoTrustOrgStoreHash`) on every read, and
  `hooks/pre_tool_use.py`'s guard now also covers both files together —
  editing the org list *and* the manifest's pin through Claude's own tools
  would otherwise let a hostile repo recompute a matching hash and defeat
  the check entirely. A missing or mismatched pin fails closed: the org
  list is ignored for that run, never silently trusted.
- Documented plainly rather than glossed over: once `allowManagedHooksOnly`
  is active, a hostile repo's *own* hooks are already blocked by Claude
  Code itself — repo-trust's remaining load-bearing value in that mode is
  `.mcp.json` MCP server risk (not a "hook," so untouched by that setting)
  and CLAUDE.md/skills/agents/commands/rules content, not hook-blocking.
  The shell guard stays necessary post-rollout for exactly the MCP-launch
  timing gap, not less necessary.

**Multi-language injection-phrasing detection**, via a different design
than "translate the patterns into more languages": `INJECTION_PATTERNS` is
now `INJECTION_PATTERNS_BY_LANG` (English, plus a new maintainer-reviewed
Swedish set), with every verified language's patterns applied
unconditionally to every natural-language surface — never gated behind a
language guess. Separately, every paragraph (not the whole file) of every
natural-language surface is checked for whether its language is one of the
verified ones; a paragraph that isn't produces a WARN saying exactly what
is and isn't covered, instead of an unverified language silently reading as
"no injection phrasing found, therefore clean." Classification is
stdlib-only: Unicode-script detection (unconditional, catches non-Latin
content even as a single token) plus a small stopword-frequency check for
Latin-script text (gated behind a minimum word count, since very short text
can't be reliably classified either way).

Design review caught the naive version of this classifying whole files
instead of paragraphs — which would have let an attacker keep a `CLAUDE.md`
dominantly English and hide the actual injected instruction in one short
non-English sentence, evading both the language patterns (wrong language)
and the coverage warning (file reads as "English, verified"). Fixed by
classifying per paragraph before either shipped.

An optional, opt-in, network-requiring `--deep-language-check` (send only
the already-flagged paragraphs to an LLM for a direct semantic judgment,
rather than translate-then-regex) is scoped as a Roadmap item, not built
this release — it's a deliberate, explicit break from the zero-dependency
default the rest of the tool holds to, so it must never run implicitly.

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
