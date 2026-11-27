# shellguard

A guard for the shell commands a coding agent runs. It plugs into Claude Code as a `PreToolUse`
hook, parses every Bash command with a real shell parser ([mvdan.cc/sh](https://github.com/mvdan/sh),
zsh and bash) and stops the ones that can do irreversible damage — also in auto mode, also when
the command is wrapped in `bash -c`, `sudo`, `xargs`, `eval` or a subshell.

It also gives a new or existing project a quick start: a `CLAUDE.md` with working rules, a
project rule file, and recommended permission and auto mode settings.

| Risk | Example | Verdict |
|---|---|---|
| Deletion outside the project, its git worktrees and the temp dir | `rm -rf ~/x`, `find / -delete`, `echo > ~/.zshrc`, `rsync --delete . ~/b` | deny |
| Deletion the guard cannot resolve | `rm -rf "$DIR"`, `ls \| xargs rm` | deny |
| Write SQL to a non-local database | `psql -h db.example.com -c 'drop table t'`, `bq query 'delete …'` | deny |
| Destructive cloud call | `gcloud … delete`, `kubectl delete`, `aws s3 rm`, `terraform destroy` | deny |
| Secret reveal | `cat .env`, `kubectl get secret -o yaml`, `aws secretsmanager get-secret-value` | deny |
| Running downloaded code | `curl … \| sh`, `base64 -d \| bash` | deny |
| Change that needs a person | `kubectl apply`, `gcloud run deploy`, unclassifiable SQL, inline code that deletes | ask |
| Everything else | `go test ./...`, `rm -rf build`, `psql -h localhost …`, `kubectl get pods` | silent |

Anything it cannot parse is denied. If the guard crashes, the call is blocked. It never executes,
writes or opens the network.

**It is one layer, not a sandbox.** A compiled program, a `make` target or a script in another
language that deletes internally is invisible to it. Pair it with server-side limits: a read-only
database user for the agent, least-privilege cloud credentials, deletion protection and backups.

## Install

Requires Go 1.26+ for now (release binaries will follow).

```bash
go install github.com/Cptweirdo/shellguard@latest
```

Then register the hook, either as a plugin:

```text
/plugin marketplace add Cptweirdo/shellguard
/plugin install shellguard@shellguard
```

or directly in `~/.claude/settings.json`:

```bash
shellguard settings --hook           # print the recommended additions, hook included
shellguard settings --hook --write   # merge them in; a timestamped backup is kept
```

Use one of the two, not both. Without the binary, the plugin escalates every Bash call to a prompt
with the install hint; it never lets a command through unchecked.

## Quick start for a project

In Claude Code, with the plugin installed:

```text
/shellguard:setup
```

It surveys the project for what reaches production, writes the starters and tailors the rules,
asking before it changes existing files or your user settings. By hand:

```bash
cd your-project
shellguard init                       # .claude/shellguard.json and CLAUDE.md (never overwrites)
shellguard check 'make deploy'        # verdict for a command; nothing is executed
shellguard policy                     # roots, rules and config files in effect here
```

## Configuration

Two optional files, same format:

- `~/.claude/shellguard.json` — user. May add deletion `roots` and `disable` checks.
- `<project>/.claude/shellguard.json` — project, can be committed. **Can only add restrictions**:
  `roots` and `disable` are ignored there, because the agent being guarded can edit it.

```json
{
  "roots": ["~/scratch"],
  "rules": [
    { "match": ["make", "deploy"], "verdict": "ask", "reason": "deploys to production" },
    { "match": ["shopify", "theme", "push"], "flags": ["--live"], "verdict": "deny" }
  ],
  "sql": [
    { "match": ["./bin/cli", "db", "query"], "flags": ["-e"], "dry_run": ["--dry-run"],
      "label": "production database" }
  ],
  "secret_files": ["*.pem", "service-account*.json"],
  "no_local_database": false
}
```

- `rules[].match` is compared with the program name and its non-flag arguments; `*` matches one
  word; the first word matches by base name. `flags` (optional) must also be present. Launchers
  such as `uv run`, `npx`, `poetry run` and `bundle exec` are looked through.
- `sql[]` names commands that carry SQL to a database that matters: `flags` whose value is the
  SQL, `positional` for a trailing argument, `stdin` for a shell that reads it. Only read-only
  statements pass (`SELECT`, `SHOW`, `WITH`, `EXPLAIN` without `ANALYZE`, …); the check is a
  keyword scan biased towards "write".
- `secret_files` are file-name globs added to `.env`, `.env.*`, `*.env` (`*.example`, `*.sample`,
  `*.template` are exempt). Loading a secret file into a process stays allowed
  (`--env-file .env`, `source .env`).
- `no_local_database: true` switches off the localhost exemption for `psql`, `mysql` and
  `cockroach sql` — for projects where a localhost port is a tunnel to production.
- `disable` (user file only): `delete`, `sql`, `cloud`, `secrets`.

Deletions are acceptable strictly below: the project directory (`$CLAUDE_PROJECT_DIR`), its git
worktrees, `$TMPDIR`, `/tmp`, user `roots` and `SHELLGUARD_ROOTS` (colon-separated). The home
directory and the filesystem root are never accepted as roots. A broken config file escalates
every command to `ask` until it is fixed.

## Recommended settings

`shellguard settings` prints the additions it recommends for `~/.claude/settings.json`:
deny/ask rules for the usual destructive spellings, and an `autoMode` block that tells the auto
mode classifier what to refuse. Add your project's facts to `autoMode.environment` (which
account is production, what is local). Every list keeps `"$defaults"`, so the built-in rules stay.

## Testing a change

Never test the guard by running a guarded command: if it has a hole, the command runs.

```bash
go test ./...
shellguard check 'rm -rf ~/x'                       # exit 0 allow, 1 ask, 2 deny
echo '{"tool_name":"Bash","cwd":"'"$PWD"'","tool_input":{"command":"rm -rf ~/x"}}' | shellguard hook
```

## Licence

MIT
