# Security Policy

repo-trust is a security tool, so bugs in it have outsized consequences — a
false `TRUSTED` verdict, a bypass of the `PreToolUse` guard, a way to forge
a signed approval, or a way to make the shell guard let a bad launch
through are all worth reporting privately rather than as a public issue.

## Reporting a vulnerability

Please do not open a public GitHub issue for a suspected security problem.

Instead, open a private [GitHub Security Advisory](../../security/advisories/new)
for this repository, or email the maintainer directly if that's not
available to you, with:

- what you found and why it matters (a false-trust scenario, a bypass, a
  way to corrupt or forge the trust store, etc.)
- the smallest reproduction you can manage — a scratch repo layout and the
  exact `repo-trust` command is usually enough
- the version (`repo-trust --version`) and platform you tested on

We'll acknowledge reports as quickly as we can and aim to have a fix or a
documented mitigation before any public disclosure.

## Scope

In scope: `repo_trust.py`, the three hooks under `hooks/`, and
`shell/guard.sh`. Anything that lets a repo's Claude configuration reach
outside the repo, tamper with the trust store, or launch `claude` against
an unapproved/drifted/tampered repo without repo-trust surfacing it is a
valid finding.

Out of scope, and already documented as accepted limitations rather than
bugs — see the README's [Threat model & known limitations](README.md#threat-model--known-limitations)
section before reporting these: heuristic detection missing novel
obfuscation, `SessionStart` being unable to block a session on its own,
the desktop app / IDE extensions not being covered by the shell guard, and
an attacker who can already read `~/.claude/security/trust.key` forging a
valid signature (that's a same-user-code-execution problem no userspace
file scheme fully closes).
