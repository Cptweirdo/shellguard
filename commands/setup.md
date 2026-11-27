---
description: Set this project up for Claude Code safely - CLAUDE.md, shellguard rules for its production commands, recommended user settings
---

Set up the current project for safe work with Claude Code using shellguard. Work through the steps
in order and stop for the user's confirmation where a step says so.

1. **Binary.** Run `shellguard version`. If it is missing, tell the user to install it
   (`go install github.com/Cptweirdo/shellguard@latest`, or a release binary) and stop.

2. **Survey, read-only.** Find what in this project reaches production or real data: deploy
   scripts and CI config, Makefile/justfile/package.json scripts, a project CLI, database
   connection code and SQL shells, infrastructure-as-code, cloud CLIs used in docs, publish and
   upload steps, files that hold secrets (`.env*`, key files, credential JSON). Read the existing
   `CLAUDE.md`, `.claude/settings.json` and `.claude/hooks/` if present. Never print the contents
   of a secret file; its name is enough.

3. **Starters.** Run `shellguard init`. It never overwrites an existing `CLAUDE.md` or
   `.claude/shellguard.json`.
   - New `CLAUDE.md`: fill in the Project, Commands and Production sections from the survey.
   - Existing `CLAUDE.md`: propose adding the "Working rules" block from the shellguard template
     (and a Production section if there is none), as a diff. Apply only after the user agrees.

4. **Project rules.** Replace the examples in `.claude/shellguard.json` with this project's real
   commands from step 2: `ask` for deploys and publishes, `deny` for data wipes and live pushes,
   an `sql` entry for every command that sends SQL to a non-local database, `secret_files` for
   secret files beyond `.env*`. Show each rule's verdict with `shellguard check '<command>'` —
   it executes nothing. Never test a rule by running the real command.

5. **User settings.** Show `shellguard settings`. Explain the deny/ask rules and the `autoMode`
   text, suggest project facts for `autoMode.environment` (what is production, what is local).
   Merge with `shellguard settings --write` only after the user agrees; it keeps a backup.

6. **Report.** `shellguard policy`, the files written or changed, what still needs the user
   (server-side controls: read-only database users, cloud IAM, deletion protection, backups).
