package guard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// File is the on-disk configuration, read from the user file
// (~/.claude/shellguard.json) and the project file
// (<project>/.claude/shellguard.json).
//
// The project file can only add restrictions: its "roots" and "disable" are
// ignored, because the agent the guard watches can edit that file.
type File struct {
	Comment string `json:"comment,omitempty"`

	// Roots are extra directories below which deletions are acceptable.
	// User file only.
	Roots []string `json:"roots,omitempty"`

	// Rules are project-specific commands to refuse or to ask about.
	Rules []Rule `json:"rules,omitempty"`

	// SQL describes project commands that send SQL to a database that
	// matters. Their statements must be read-only.
	SQL []SQLWrapper `json:"sql,omitempty"`

	// SecretFiles are file-name globs whose contents must not be printed or
	// copied, in addition to the built-in .env patterns.
	SecretFiles []string `json:"secret_files,omitempty"`

	// NoLocalDatabase: no database reachable from this machine is disposable
	// (for example a localhost port tunnelled to production). The localhost
	// exemption for psql, mysql and cockroach sql is switched off.
	NoLocalDatabase bool `json:"no_local_database,omitempty"`

	// Disable switches built-in checks off: "delete", "sql", "cloud",
	// "secrets". User file only.
	Disable []string `json:"disable,omitempty"`
}

// Rule matches a command by its leading words.
//
// Match is compared with the program name followed by its non-flag arguments:
// ["shopify", "theme", "push"] matches `shopify theme push --live`. "*"
// matches any one word. Flags, when given, must also be present (any of them).
type Rule struct {
	Comment string   `json:"comment,omitempty"`
	Match   []string `json:"match"`
	Flags   []string `json:"flags,omitempty"`
	Verdict string   `json:"verdict"` // "deny" or "ask"
	Reason  string   `json:"reason,omitempty"`
}

// SQLWrapper names a command that carries SQL to a non-local database.
type SQLWrapper struct {
	Comment string   `json:"comment,omitempty"`
	Match   []string `json:"match"`
	// Flags are the options whose value is the SQL, e.g. ["-e", "--execute"].
	Flags []string `json:"flags,omitempty"`
	// Positional: the last positional argument is the SQL.
	Positional bool `json:"positional,omitempty"`
	// Stdin: the command reads SQL from standard input.
	Stdin bool `json:"stdin,omitempty"`
	// DryRun flags make the command harmless; the check is skipped.
	DryRun []string `json:"dry_run,omitempty"`
	// Label names the target in messages, e.g. "production Postgres".
	Label string `json:"label,omitempty"`
}

var defaultSecretFiles = []string{".env", ".env.*", "*.env"}

// Suffixes of files that only look like secret files.
var secretExempt = []string{".example", ".sample", ".template", ".dist", ".defaults"}

func readFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var f File
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	for i, r := range f.Rules {
		if len(r.Match) == 0 {
			return nil, fmt.Errorf("rules[%d]: match is empty", i)
		}
		if r.Verdict != "deny" && r.Verdict != "ask" {
			return nil, fmt.Errorf("rules[%d]: verdict must be \"deny\" or \"ask\"", i)
		}
	}
	for i, w := range f.SQL {
		if len(w.Match) == 0 {
			return nil, fmt.Errorf("sql[%d]: match is empty", i)
		}
		if len(w.Flags) == 0 && !w.Positional && !w.Stdin {
			return nil, fmt.Errorf("sql[%d]: set flags, positional or stdin", i)
		}
	}
	for _, p := range f.SecretFiles {
		if _, err := filepath.Match(p, "x"); err != nil {
			return nil, fmt.Errorf("secret_files: bad pattern %q", p)
		}
	}
	return &f, nil
}

// UserConfigPath is where the per-user configuration lives.
func UserConfigPath(home string) string {
	if p := os.Getenv("SHELLGUARD_CONFIG"); p != "" {
		return p
	}
	return filepath.Join(home, ".claude", "shellguard.json")
}

// ProjectConfigPath is where a project's configuration lives.
func ProjectConfigPath(project string) string {
	return filepath.Join(project, ".claude", "shellguard.json")
}

// rootPath resolves a root directory completely, the last component too, so
// that a target reached through a symlinked root still lies below it.
func rootPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return realpath(p)
}

func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

// configFromEnv builds the policy for one call from the environment and the
// two configuration files.
func configFromEnv(cwd string) config {
	home, _ := os.UserHomeDir()
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	c := config{home: home, cwd: cwd, tmpdir: os.Getenv("TMPDIR"), secretFiles: defaultSecretFiles}
	disabled := map[string]bool{}

	addRoot := func(p string) {
		if p = strings.TrimSpace(p); p == "" {
			return
		}
		p = rootPath(expandHome(p, home))
		// Never accept the filesystem root, the home directory or one of
		// its ancestors as a place where everything may be deleted.
		h := rootPath(home)
		if p == "/" || p == h || under(h, p, false) {
			c.problems = append(c.problems, fmt.Sprintf("root %q is the home directory or above it; ignored", p))
			return
		}
		c.roots = append(c.roots, p)
	}

	for _, r := range strings.Split(os.Getenv("SHELLGUARD_ROOTS"), ":") {
		addRoot(r)
	}
	userPath := UserConfigPath(home)
	if f, err := readFile(userPath); err != nil {
		c.problems = append(c.problems, fmt.Sprintf("%s: %v", userPath, err))
	} else if f != nil {
		for _, r := range f.Roots {
			addRoot(r)
		}
		for _, d := range f.Disable {
			disabled[d] = true
		}
		c.rules = append(c.rules, f.Rules...)
		c.sql = append(c.sql, f.SQL...)
		c.secretFiles = append(c.secretFiles, f.SecretFiles...)
		c.noLocalDB = c.noLocalDB || f.NoLocalDatabase
	}
	for _, t := range []string{c.tmpdir, "/tmp", "/private/tmp"} {
		if t != "" {
			c.roots = append(c.roots, rootPath(t))
		}
	}

	// The session's project directory is a root too, unless it is the home
	// directory, an ancestor of it, or something as shallow as a volume root.
	if p := os.Getenv("CLAUDE_PROJECT_DIR"); p != "" {
		p = rootPath(p)
		h := rootPath(home)
		shallow := strings.Count(p, string(filepath.Separator)) < 3
		if p != h && !under(h, p, false) && !shallow {
			c.project = p
			c.roots = append(c.roots, worktrees(p)...)
			projPath := ProjectConfigPath(p)
			if f, err := readFile(projPath); err != nil {
				c.problems = append(c.problems, fmt.Sprintf("%s: %v", projPath, err))
			} else if f != nil {
				// Additive only: roots and disable are not honoured here.
				c.rules = append(c.rules, f.Rules...)
				c.sql = append(c.sql, f.SQL...)
				c.secretFiles = append(c.secretFiles, f.SecretFiles...)
				c.noLocalDB = c.noLocalDB || f.NoLocalDatabase
			}
		}
	}
	c.disabled = disabled
	return c
}

// worktrees returns the other git worktrees of the project, read from the
// repository's metadata (no git process is started). An agent working in one
// worktree routinely cleans up in its siblings.
func worktrees(project string) []string {
	gitPath := filepath.Join(project, ".git")
	info, err := os.Lstat(gitPath)
	if err != nil {
		return nil
	}
	common := gitPath
	if !info.IsDir() {
		// A linked worktree: ".git" is a file "gitdir: <main>/.git/worktrees/<name>".
		data, err := os.ReadFile(gitPath)
		if err != nil {
			return nil
		}
		line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(data)), "gitdir:"))
		if !filepath.IsAbs(line) {
			line = filepath.Join(project, line)
		}
		common = filepath.Dir(filepath.Dir(line)) // .../.git
		if filepath.Base(common) != ".git" {
			return nil
		}
	}
	var out []string
	if main := filepath.Dir(common); main != project {
		out = append(out, rootPath(main))
	}
	entries, err := os.ReadDir(filepath.Join(common, "worktrees"))
	if err != nil {
		return out
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(common, "worktrees", e.Name(), "gitdir"))
		if err != nil {
			continue
		}
		wt := filepath.Dir(strings.TrimSpace(string(data)))
		if filepath.IsAbs(wt) && strings.Count(wt, string(filepath.Separator)) >= 3 {
			out = append(out, rootPath(wt))
		}
	}
	return out
}

// matchWords reports whether the command (program name, then its literal
// non-flag arguments) starts with the pattern.
func matchWords(pattern []string, name string, args []wv) bool {
	words := []string{name}
	for _, a := range args {
		if !a.lit {
			break
		}
		if strings.HasPrefix(a.s, "-") {
			continue
		}
		words = append(words, a.s)
		if len(words) >= len(pattern) {
			break
		}
	}
	if len(words) < len(pattern) {
		return false
	}
	for i, p := range pattern {
		if i == 0 {
			p = filepath.Base(p)
		}
		if p != "*" && p != words[i] {
			return false
		}
	}
	return true
}

// custom applies the configured rules and SQL wrappers to one command.
func (sc *scope) custom(name string, args []wv, c ctx) {
	g := sc.g
	for _, r := range g.cfg.rules {
		if !matchWords(r.Match, name, args) {
			continue
		}
		if len(r.Flags) > 0 && !hasFlagPrefix(args, r.Flags...) {
			continue
		}
		reason := r.Reason
		if reason == "" {
			reason = "matches a configured rule"
		}
		level := ask
		if r.Verdict == "deny" {
			level = deny
		}
		g.hard(level, "%s: %s", strings.Join(r.Match, " "), reason)
	}
	if g.cfg.disabled["sql"] {
		return
	}
	for _, w := range g.cfg.sql {
		if !matchWords(w.Match, name, args) {
			continue
		}
		if len(w.DryRun) > 0 && hasFlagPrefix(args, w.DryRun...) {
			continue
		}
		where := w.Label
		if where == "" {
			where = strings.Join(w.Match, " ")
		}
		found := false
		if len(w.Flags) > 0 {
			vals, _ := flagValues(args, w.Flags)
			for _, v := range vals {
				found = true
				sc.judgeSQL(where, v)
			}
		}
		if !found && w.Positional {
			if pos := positionals(args, ""); len(pos) >= len(w.Match) {
				found = true
				sc.judgeSQL(where, pos[len(pos)-1])
			}
		}
		if !found && w.Stdin {
			sc.judgeStdinSQL(where, c)
		}
	}
}

func (c config) isSecretFile(path string) bool {
	if c.disabled["secrets"] || path == "" {
		return false
	}
	base := filepath.Base(path)
	for _, s := range secretExempt {
		if strings.HasSuffix(base, s) {
			return false
		}
	}
	for _, p := range c.secretFiles {
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
	}
	return false
}

// Programs that print, transform or copy what they are given. A secret file
// may be loaded into a process (source, --env-file); it may not be shown or
// moved somewhere the guard no longer covers.
var revealers = set(
	"cat", "bat", "tac", "nl", "less", "more", "head", "tail", "strings", "od", "xxd", "hexdump",
	"base64", "base32", "cut", "awk", "gawk", "sed", "grep", "egrep", "fgrep", "rg", "ag", "ack",
	"sort", "uniq", "tr", "column", "paste", "tee", "diff", "cmp", "jq", "yq", "wc", "open", "pbcopy",
	"cp", "mv", "install", "ln", "rsync", "scp", "sftp", "tar", "zip", "gzip", "7z", "curl", "wget",
	"nc", "ncat", "socat", "gh", "aws", "gcloud", "gsutil", "dd", "printenv",
)

func (sc *scope) secretFiles(name string, args []wv, c ctx) {
	g := sc.g
	if g.cfg.disabled["secrets"] {
		return
	}
	gitAdd := name == "git" && has(args, "add")
	if !revealers[name] && !gitAdd {
		return
	}
	for _, a := range args {
		if !a.lit {
			continue
		}
		cands := []string{a.s}
		if _, v, ok := strings.Cut(a.s, "="); ok {
			cands = append(cands, v)
		}
		for _, cand := range cands {
			cand = strings.TrimPrefix(cand, "@")
			if i := strings.LastIndex(cand, ":"); i >= 0 {
				cand = cand[i+1:]
			}
			if g.cfg.isSecretFile(cand) {
				g.hard(deny, "%s on %s would reveal or copy a secret file; load it into a process instead (source, --env-file)", name, filepath.Base(cand))
				return
			}
		}
	}
}
