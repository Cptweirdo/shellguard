# CLAUDE.md

<!-- Starter written by `shellguard init`. Fill in the project sections, keep the working rules,
     delete these comments. Keep the file short: every line is read on every session. -->

## Project

<!-- One paragraph: what this is, the main directories, the stack. -->

## Commands

```bash
# test:   <the command that runs the tests>
# lint:   <the linter / formatter>
# build:  <how to build>
# run:    <how to start it locally>
```

## Production

<!-- What reaches real users or real data, and how. Name each command. Example:
- `make deploy` deploys to production. Confirm first.
- `./bin/cli db shell` opens the production database. Read-only queries only.
Mirror every entry here in .claude/shellguard.json so it is enforced, not only described. -->

## Working rules

**Safety**
- Anything outward-facing or hard to undo — deploy, publish, push to a shared branch, send a
  message, write to a production system, delete outside the repo — is confirmed with the user
  first. An earlier yes covers that one action, not the next one.
- Production databases get read-only statements. Writes, migrations and data fixes are run by the
  user in their own terminal.
- Secret values are never printed, copied or summarised: `.env` files, key files, keychain
  entries, secret-manager values. Use them opaquely (`--env-file`, `source`, a script that loads
  them); validate with a check that prints a verdict, not the value.
- Never test a guard, deny rule or hook by running the command it guards. If the guard has a hole,
  the command runs. Test offline (`shellguard check '<cmd>'`, sample hook input) or ask the user.
- Before deleting or overwriting, look at the target. Prefer moving to a scratch directory over
  `rm -rf` when unsure.

**Work**
- Read the code before changing it; follow the patterns already there. Small, focused diffs.
- A change is done when its tests and linters pass. Run them; do not assume.
- Report what was verified and what was not. A skipped step or a failing test is said plainly,
  with the output.
- Ask only when the answer changes what you do next. Otherwise pick the sensible default, say
  which one, and continue.
- Parallel work goes in a git worktree, not in the main checkout. Never `git stash` in a shared
  repository; use a WIP commit.
- Commit or push only when asked. Never `--no-verify`, never force-push a shared branch.

**Writing**
- Code, comments, commits and docs in English. Comments say why, not what.
- New files are named at the end of the reply.
