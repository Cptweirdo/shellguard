# CLAUDE.md

shellguard is a Claude Code `PreToolUse` hook (and a small CLI) that parses every Bash command
with a real shell parser and stops the ones that can do irreversible damage. It is also a quick
start for setting up a project for Claude Code safely (`shellguard init`, `shellguard settings`).

## Layout

- `main.go` — CLI: `hook`, `check`, `policy`, `init`, `settings`, `version`.
- `internal/guard/` — the analysis. `guard.go` walks the parsed command (wrappers, nesting, paths,
  deletions), `sql.go` the SQL clients and the keyword classifier, `cloud.go` gcloud, kubectl,
  gsutil, helm, terraform, aws, `config.go` the config files, project rules and secret files,
  `api.go` the exported `Check` / `Describe`.
- `templates/` — embedded starters: `CLAUDE.md`, `shellguard.json`, `settings.json`.
- `.claude-plugin/`, `hooks/` — the Claude Code plugin and its marketplace entry.

## Commands

```bash
go test ./...                     # unit tests; the verdict tables run nothing
go vet ./... && gofmt -l .        # must be clean
go build -o shellguard .
./shellguard check 'rm -rf ~'     # one verdict by hand; nothing is executed
```

## Rules for this codebase

- **Fail closed.** A parse error, an unknown construct or a broken config ends in `ask` or `deny`,
  never in silence. A panic in the hook exits 2, which blocks the call.
- **The guard never executes, writes or opens the network.** Reading files (configs, a script about
  to run, git worktree metadata) is the limit.
- **The project config can only add restrictions.** `roots` and `disable` are honoured from the
  user file only: the agent being guarded can edit project files.
- **Every behaviour change starts as a row in a test table** (`guard_test.go`, `config_test.go`):
  a missed case or a false positive is written down first, then fixed.
- **Never verify the guard by running a guarded command for real.** Use the tables or
  `shellguard check`.
- **Nothing specific to one user or company in this repository**: no real hostnames, project ids,
  paths, names or credentials, in code, tests or docs. Examples use `/work/src/app`, `mycli`,
  `example.com`.
- Dependencies stay minimal: the standard library and `mvdan.cc/sh/v3`.

## Working rules

- Confirm anything outward-facing or hard to undo (a release, a tag, a push to `main`) first.
- Secret values are never printed or copied, including in test fixtures.
- Small, focused diffs; read the surrounding code first; run the tests before calling it done.
- Report what was verified and what was not, plainly.
- Code, comments, commits and docs in English; comments say why.
