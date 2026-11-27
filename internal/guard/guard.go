package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	allow = iota
	ask
	deny
)

const maxDepth = 6

// config is the resolved policy for one hook call.
type config struct {
	home    string
	cwd     string
	tmpdir  string
	roots   []string // a deletion target must lie strictly below one of these
	project string   // session project dir; a root, but never a target itself

	rules       []Rule
	sql         []SQLWrapper
	secretFiles []string // globs on the file name
	problems    []string // config files that could not be used
	disabled    map[string]bool
	noLocalDB   bool // localhost databases are not exempt
}

type guard struct {
	cfg     config
	level   int
	reasons []string
	lenient bool // scanning a script file: only hard findings, reported as ask
	depth   int
}

func newGuard(c config) *guard { return &guard{cfg: c} }

// check returns the verdict for one Bash tool command.
func (g *guard) check(src string) (int, string) {
	for _, p := range g.cfg.problems {
		g.note(ask, "configuration problem, the guard may be incomplete: "+p)
	}
	g.analyze(src)
	if g.level == allow {
		return allow, ""
	}
	r := g.reasons
	if len(r) > 3 {
		r = append(r[:3:3], fmt.Sprintf("(+%d more)", len(g.reasons)-3))
	}
	return g.level, strings.Join(r, "; ")
}

// hard records a finding the guard is sure about.
func (g *guard) hard(level int, format string, a ...any) {
	if g.lenient && level == deny {
		level = ask
	}
	g.note(level, fmt.Sprintf(format, a...))
}

// dyn records a finding caused by something the guard cannot see through
// (a variable, a substitution). Skipped while scanning script files, where
// such constructs are the norm.
func (g *guard) dyn(level int, format string, a ...any) {
	if g.lenient {
		return
	}
	g.note(level, fmt.Sprintf(format, a...))
}

func (g *guard) note(level int, reason string) {
	if level > g.level {
		g.level = level
	}
	for _, r := range g.reasons {
		if r == reason {
			return
		}
	}
	g.reasons = append(g.reasons, reason)
}

// scope is the per-source state: one parsed command string or script.
type scope struct {
	g       *guard
	tainted map[string]bool // variable names the source assigns or reads into
	assigns map[string]int  // how often each name is assigned
	consts  map[string]constant
	hasCd   bool
	cdSafe  bool     // every cd target is a literal, resolvable path
	cdDirs  []string // where those cd calls go; a relative path is checked against each
	piped   map[*syntax.Stmt]bool
}

// constant is a variable set exactly once, at the top level of the source,
// to a literal value: "T=/tmp/x; rm -rf $T" is as checkable as the literal.
type constant struct {
	val    string
	end    uint // offset after which the value holds
	simple bool // safe to use unquoted: no spaces, globs or shell syntax
}

func parse(src string) (*syntax.File, error) {
	var firstErr error
	for _, lang := range []syntax.LangVariant{syntax.LangZsh, syntax.LangBash} {
		f, err := syntax.NewParser(syntax.Variant(lang)).Parse(strings.NewReader(src), "")
		if err == nil {
			return f, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

func (g *guard) analyze(src string) {
	if g.depth > maxDepth {
		g.hard(ask, "shell nesting too deep to analyse")
		return
	}
	f, err := parse(src)
	if err != nil {
		g.dyn(deny, "cannot parse the command (%v); run it in your own terminal", err)
		return
	}
	sc := &scope{g: g, tainted: map[string]bool{}, assigns: map[string]int{}, consts: map[string]constant{},
		cdSafe: true, piped: map[*syntax.Stmt]bool{}}
	sc.prepass(f)
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				sc.piped[x.Y] = true
			}
		case *syntax.Stmt:
			sc.stmt(x)
		}
		return true
	})
}

// prepass finds variable assignments and directory changes, which decide
// whether $HOME-style variables and relative paths can be trusted.
func (sc *scope) prepass(f *syntax.File) {
	type cdCall struct{ args []*syntax.Word }
	var cds []cdCall
	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Assign:
			if x.Name != nil {
				sc.assigns[x.Name.Value]++
			}
		case *syntax.WordIter:
			if x.Name != nil {
				sc.tainted[x.Name.Value] = true
			}
		case *syntax.CallExpr:
			for _, w := range x.Args {
				if s := w.Lit(); s != "" {
					sc.tainted[s] = true // read X, unset X, printf -v X ...
				}
			}
			if len(x.Args) > 0 {
				switch x.Args[0].Lit() {
				case "cd", "pushd", "popd", "chdir":
					cds = append(cds, cdCall{x.Args[1:]})
				}
			}
		}
		return true
	})
	for _, st := range f.Stmts {
		sc.collectConsts(st)
	}
	if len(cds) == 0 {
		return
	}
	sc.hasCd = true
	sc.tainted["PWD"] = true
	for _, c := range cds {
		var target *wv
		for _, w := range c.args {
			v := sc.word(w)
			if v.lit && strings.HasPrefix(v.s, "-") && v.s != "-" {
				continue
			}
			target = &v
			break
		}
		// A relative target is only resolvable when it is the only cd:
		// after several, the directory it is relative to is unknown.
		if target == nil || !target.lit || target.glob >= 0 || target.s == "-" ||
			(!filepath.IsAbs(target.s) && len(cds) > 1) {
			sc.cdSafe = false
			continue
		}
		p := target.s
		if !filepath.IsAbs(p) {
			p = filepath.Join(sc.g.cfg.cwd, p)
		}
		sc.cdDirs = append(sc.cdDirs, filepath.Clean(p))
	}
}

// collectConsts records top-level "NAME=literal" statements, also along &&.
func (sc *scope) collectConsts(st *syntax.Stmt) {
	if st == nil || st.Background || st.Negated {
		return
	}
	switch x := st.Cmd.(type) {
	case *syntax.BinaryCmd:
		if x.Op == syntax.AndStmt {
			sc.collectConsts(x.X)
			sc.collectConsts(x.Y)
		}
	case *syntax.CallExpr:
		if len(x.Args) != 0 {
			return
		}
		for _, a := range x.Assigns {
			if a.Name == nil || a.Append || a.Index != nil || a.Array != nil || a.Value == nil {
				continue
			}
			name := a.Name.Value
			if sc.assigns[name] != 1 || sc.tainted[name] {
				continue
			}
			v := sc.word(a.Value)
			if !v.lit || v.s == "" {
				continue
			}
			simple := v.glob < 0 && !strings.ContainsAny(v.s, " \t\n*?[]{}()<>|&;$`~!#")
			sc.consts[name] = constant{val: v.s, end: a.End().Offset(), simple: simple}
		}
	}
}

// wv is a shell word reduced to what the guard can know statically.
type wv struct {
	s    string
	lit  bool // false: contains something only the shell can expand
	glob int  // index in s of the first unquoted glob/brace char, or -1
	tail bool // the word ends in a literal "/name": the program name is known
}

// hdocWord reads a here-document body: nothing in it is a glob, and only
// expansions make it opaque.
func (sc *scope) hdocWord(w *syntax.Word) wv {
	v := wv{lit: true, glob: -1}
	if w == nil {
		return v
	}
	for _, part := range w.Parts {
		if l, ok := part.(*syntax.Lit); ok {
			v.s += l.Value
		} else {
			v.lit = false
		}
	}
	return v
}

func (sc *scope) word(w *syntax.Word) wv {
	v := wv{lit: true, glob: -1}
	if w == nil {
		return v
	}
	markGlob := func() {
		if v.glob < 0 {
			v.glob = len(v.s)
		}
	}
	for i, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			raw := p.Value
			if i == 0 {
				switch {
				case raw == "~" || strings.HasPrefix(raw, "~/"):
					if sc.tainted["HOME"] || sc.assigns["HOME"] > 0 || sc.g.cfg.home == "" {
						v.lit = false
					}
					v.s += sc.g.cfg.home
					raw = raw[1:]
				case raw == "{}" && len(w.Parts) == 1:
					// find/xargs placeholder
					v.s += raw
					raw = ""
				case strings.HasPrefix(raw, "~"), strings.HasPrefix(raw, "="), strings.HasPrefix(raw, "{"):
					// ~user, zsh =cmd, leading brace expansion
					v.lit = false
				}
			}
			for j := 0; j < len(raw); j++ {
				c := raw[j]
				switch c {
				case '\\':
					if j+1 < len(raw) {
						j++
						if raw[j] != '\n' {
							v.s += string(raw[j])
						}
					}
				case '*', '?', '[', '{':
					markGlob()
					v.s += string(c)
				case '(', ')', '<', '>', '^', '#':
					// zsh glob qualifiers and extended globs can run code
					if v.glob >= 0 || c == '(' || c == '<' {
						v.lit = false
					}
					v.s += string(c)
				default:
					v.s += string(c)
				}
			}
		case *syntax.SglQuoted:
			if p.Dollar && strings.Contains(p.Value, `\`) {
				v.lit = false
			}
			v.s += p.Value
		case *syntax.DblQuoted:
			if p.Dollar {
				v.lit = false
			}
			for _, ip := range p.Parts {
				switch q := ip.(type) {
				case *syntax.Lit:
					v.s += unescapeDq(q.Value)
				case *syntax.ParamExp:
					s, ok := sc.param(q, true)
					v.s += s
					v.lit = v.lit && ok
				default:
					v.lit = false
				}
			}
		case *syntax.ParamExp:
			s, ok := sc.param(p, false)
			v.s += s
			v.lit = v.lit && ok
		case *syntax.ExtGlob, *syntax.BraceExp:
			markGlob()
			v.s += "*"
			v.lit = false
		default: // command/arithmetic/process substitution
			v.lit = false
		}
	}
	if n := len(w.Parts); n > 0 {
		if l, ok := w.Parts[n-1].(*syntax.Lit); ok && strings.Contains(l.Value, "/") && !strings.HasSuffix(l.Value, "/") {
			v.tail = true
		}
	}
	return v
}

func unescapeDq(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.ContainsRune("\"\\$`\n", rune(s[i+1])) {
			i++
			if s[i] == '\n' {
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// param resolves $HOME, $TMPDIR and $PWD when nothing in the source could
// have changed them. Every other parameter is opaque.
func (sc *scope) param(p *syntax.ParamExp, quoted bool) (string, bool) {
	if p.Param == nil || p.Excl || p.Length || p.Width || p.IsSet || p.Index != nil ||
		p.Slice != nil || p.Repl != nil || p.Exp != nil || p.Flags != nil ||
		p.NestedParam != nil || len(p.Modifiers) > 0 || p.Names != 0 {
		return "", false
	}
	name := p.Param.Value
	switch name {
	case "$", "!", "RANDOM", "PPID", "EPOCHSECONDS", "SECONDS", "LINENO":
		return "0", true // digits only: cannot add a slash or a dot-dot
	}
	if c, ok := sc.consts[name]; ok && p.Pos().Offset() >= c.end && (quoted || c.simple) {
		return c.val, true
	}
	if sc.tainted[name] || sc.assigns[name] > 0 {
		return "", false
	}
	var val string
	switch name {
	case "HOME":
		val = sc.g.cfg.home
	case "TMPDIR":
		val = sc.g.cfg.tmpdir
	case "PWD":
		val = sc.g.cfg.cwd
	}
	return val, val != ""
}

// ctx carries what surrounds one simple command.
type ctx struct {
	hdoc    *wv             // here-document or here-string feeding stdin
	piped   bool            // stdin comes from a pipe
	env     map[string]bool // VAR=... prefixes
	remote  bool            // runs somewhere else (kubectl exec): never "local"
	dynTail bool            // more arguments arrive at run time (xargs)
}

func (c ctx) envPrefix(prefixes ...string) bool {
	for name := range c.env {
		for _, p := range prefixes {
			if strings.HasPrefix(name, p) {
				return true
			}
		}
	}
	return false
}

func (sc *scope) stmt(st *syntax.Stmt) {
	c := ctx{piped: sc.piped[st], env: map[string]bool{}}
	for _, r := range st.Redirs {
		switch r.Op {
		case syntax.RdrOut, syntax.RdrClob, syntax.RdrAll, syntax.RdrAllClob, syntax.RdrInOut:
			sc.clobber("redirect", sc.word(r.Word), false)
		case syntax.RdrIn:
			if v := sc.word(r.Word); v.lit && sc.g.cfg.isSecretFile(v.s) {
				sc.g.hard(deny, "reading %s would reveal a secret file", v.s)
			}
		case syntax.Hdoc, syntax.DashHdoc:
			v := sc.hdocWord(r.Hdoc)
			c.hdoc = &v
		case syntax.WordHdoc:
			v := sc.word(r.Word)
			c.hdoc = &v
		}
	}
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return
	}
	for _, a := range call.Assigns {
		if a.Name != nil {
			c.env[a.Name.Value] = true
		}
	}
	words := make([]wv, len(call.Args))
	for i, w := range call.Args {
		words[i] = sc.word(w)
	}
	sc.cmd(words, c)
}

var flagsWithValue = map[string]string{
	"sudo":       "ughpCDRT",
	"doas":       "uC",
	"nice":       "n",
	"caffeinate": "tw",
	"timeout":    "sk",
	"gtimeout":   "sk",
	"exec":       "a",
	"stdbuf":     "ioe",
	"xargs":      "IJLnPsERS",
	"ionice":     "cnp",
}

// cmd strips wrapper commands (sudo, env, xargs, ...) and dispatches on the
// real program.
func (sc *scope) cmd(words []wv, c ctx) {
	g := sc.g
	for hops := 0; hops < 12; hops++ {
		if len(words) == 0 {
			return
		}
		if !words[0].lit && !words[0].tail {
			g.dyn(ask, "command name is computed at run time")
			return
		}
		name := filepath.Base(words[0].s)
		switch name {
		case "sudo", "doas", "nice", "caffeinate", "timeout", "gtimeout", "exec", "stdbuf",
			"xargs", "ionice", "command", "builtin", "nohup", "noglob", "nocorrect", "time", "setsid":
			if name == "command" && len(words) > 1 && (words[1].s == "-v" || words[1].s == "-V") {
				return // a lookup, not an execution
			}
			if name == "xargs" {
				c.dynTail = true
			}
			valued := flagsWithValue[name]
			i := 1
			for i < len(words) && strings.HasPrefix(words[i].s, "-") && words[i].lit {
				f := words[i].s
				i++
				if f == "--" {
					break
				}
				if len(f) == 2 && strings.ContainsRune(valued, rune(f[1])) {
					i++
				}
			}
			if (name == "timeout" || name == "gtimeout") && i < len(words) {
				i++ // the duration
			}
			if i > len(words) {
				i = len(words)
			}
			words = words[i:]
		case "env":
			i := 1
			for i < len(words) {
				w := words[i]
				if !w.lit {
					break
				}
				if w.s == "-u" || w.s == "-C" || w.s == "-P" {
					i += 2
					continue
				}
				if w.s == "-S" || strings.HasPrefix(w.s, "--split-string") {
					g.dyn(ask, "env -S hides the command")
					return
				}
				if strings.HasPrefix(w.s, "-") {
					i++
					continue
				}
				if eq := strings.Index(w.s, "="); eq > 0 {
					c.env[w.s[:eq]] = true
					i++
					continue
				}
				break
			}
			if i > len(words) {
				i = len(words)
			}
			words = words[i:]
		case "uv", "uvx", "npx", "bunx", "pnpm", "npm", "yarn", "poetry", "pipenv", "bundle", "pdm", "hatch", "rye", "mise", "dotenvx":
			rest, ok := runner(name, words)
			if !ok {
				sc.dispatch(name, words, c)
				return
			}
			words = rest
		default:
			sc.dispatch(name, words, c)
			return
		}
	}
	g.dyn(ask, "too many wrapper commands")
}

// runnerSub maps a launcher to the subcommand that runs another program
// ("" means the launcher runs its first positional directly).
var runnerSub = map[string][]string{
	"uv": {"run"}, "uvx": {""}, "npx": {""}, "bunx": {""},
	"pnpm": {"exec", "dlx"}, "npm": {"exec"}, "yarn": {"exec", "dlx"},
	"poetry": {"run"}, "pipenv": {"run"}, "bundle": {"exec"}, "pdm": {"run"},
	"hatch": {"run"}, "rye": {"run"}, "mise": {"exec", "x"}, "dotenvx": {"run"},
}

var runnerValued = set("--env-file", "--with", "--with-requirements", "--python", "-p", "--project", "--directory",
	"--group", "--extra", "--package", "--from", "--index", "--with-editable", "--script", "-c", "--call", "-f", "-C")

// runner strips a launcher such as "uv run" and returns the program it runs.
func runner(name string, words []wv) ([]wv, bool) {
	i := 1
	skipFlags := func() {
		for i < len(words) && words[i].lit && strings.HasPrefix(words[i].s, "-") {
			f := words[i].s
			i++
			if f == "--" {
				return
			}
			if runnerValued[f] && i < len(words) {
				i++
			}
		}
	}
	skipFlags()
	subs := runnerSub[name]
	if subs[0] != "" {
		if i >= len(words) {
			return nil, false
		}
		found := false
		for _, s := range subs {
			if words[i].s == s {
				found = true
			}
		}
		if !found {
			return nil, false
		}
		i++
		skipFlags()
	}
	if i >= len(words) {
		return nil, false
	}
	return words[i:], true
}

var (
	shells       = set("sh", "bash", "zsh", "dash", "ksh", "fish")
	interpreters = map[string][]string{
		"python": {"-c"}, "python3": {"-c"}, "python2": {"-c"},
		"node": {"-e", "--eval", "-p", "--print"}, "bun": {"-e", "--eval"}, "deno": {"eval"},
		"perl": {"-e", "-E"}, "ruby": {"-e"}, "php": {"-r"}, "osascript": {"-e"},
	}
	rmLike = set("rm", "rmdir", "unlink", "shred", "srm", "trash")
)

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func (sc *scope) dispatch(name string, w []wv, c ctx) {
	g := sc.g
	args := w[1:]
	sc.custom(name, args, c)
	sc.secretFiles(name, args, c)
	// pythonX.Y and friends
	base := name
	if strings.HasPrefix(name, "python") {
		base = "python"
	}
	switch {
	case shells[name]:
		sc.shell(args, c)
	case name == "eval":
		var parts []string
		for _, a := range args {
			if !a.lit {
				g.dyn(ask, "eval of a computed string")
				return
			}
			parts = append(parts, a.s)
		}
		sc.nested(strings.Join(parts, " "))
	case name == "source" || name == ".":
		if len(args) > 0 {
			sc.scanFile(args[0])
		}
	case strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".zsh") || strings.HasSuffix(name, ".bash"):
		sc.scanFile(w[0])
	case interpreters[base] != nil:
		sc.interpreter(name, interpreters[base], args, c)
	case rmLike[name]:
		sc.remove(name, args, c)
	case name == "mv":
		for _, t := range positionals(args, "t") {
			if t.lit {
				if st := sc.pathStatus(t); st == pathOutside {
					g.hard(ask, "mv touches a path outside the allowed roots: %s", t.s)
				}
			}
		}
	case name == "rsync":
		sc.rsync(args)
	case name == "truncate":
		for _, t := range positionals(args, "sr") {
			sc.clobber("truncate", t, true)
		}
	case name == "tee":
		for _, t := range positionals(args, "") {
			sc.clobber("tee", t, false)
		}
	case name == "dd":
		for _, a := range args {
			if strings.HasPrefix(a.s, "of=") {
				t := a
				t.s = a.s[3:]
				if t.glob >= 3 {
					t.glob -= 3
				}
				sc.clobber("dd", t, true)
			}
		}
	case name == "find" || name == "gfind":
		sc.find(args, c)
	case name == "diskutil":
		if len(args) > 0 {
			v := strings.ToLower(args[0].s)
			if strings.HasPrefix(v, "erase") || strings.HasPrefix(v, "partition") ||
				strings.HasPrefix(v, "zero") || strings.HasPrefix(v, "secureerase") ||
				strings.HasPrefix(v, "reformat") || (v == "apfs" && has(args, "deleteVolume", "deleteContainer", "eraseVolume")) {
				g.hard(deny, "diskutil %s destroys a volume", args[0].s)
			}
		}
	case name == "tmutil":
		if has(args, "delete", "deletelocalsnapshots", "deleteinprogress") {
			g.hard(deny, "tmutil delete removes backups")
		}
	case strings.HasPrefix(name, "mkfs") || strings.HasPrefix(name, "newfs"):
		g.hard(deny, "%s formats a filesystem", name)
	case name == "security":
		if has(args, "dump-keychain") || (has(args, "find-generic-password", "find-internet-password") && hasFlagLetter(args, "wg")) {
			g.hard(deny, "would print a keychain secret")
		}
	case name == "mysql" || name == "mariadb":
		sc.sqlClient(name, args, c, []string{"-e", "--execute"}, nil)
	case name == "aws":
		sc.aws(args, c)
	case name == "cockroach" || name == "cockroach-sql":
		if name == "cockroach-sql" || has(args, "sql") {
			sc.sqlClient("cockroach sql", args, c, []string{"-e", "--execute"}, []string{"-f", "--file"})
		}
	case name == "psql":
		sc.sqlClient("psql", args, c, []string{"-c", "--command"}, []string{"-f", "--file"})
	case name == "bq":
		sc.bq(args, c)
	case name == "gcloud":
		sc.gcloud(args, c)
	case name == "kubectl" || name == "oc":
		sc.kubectl(args, c)
	case name == "gsutil":
		sc.gsutil(args, c)
	case name == "helm":
		sc.helm(args)
	case name == "terraform" || name == "tofu":
		sc.terraform(name, args)
	}
}

func has(args []wv, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a.s == n {
				return true
			}
		}
	}
	return false
}

// hasFlagLetter reports whether a short flag cluster contains one of letters.
func hasFlagLetter(args []wv, letters string) bool {
	for _, a := range args {
		if strings.HasPrefix(a.s, "-") && !strings.HasPrefix(a.s, "--") && strings.ContainsAny(a.s[1:], letters) {
			return true
		}
	}
	return false
}

// positionals returns the non-flag arguments. valued lists the short flags
// that consume the next argument.
func positionals(args []wv, valued string) []wv {
	var out []wv
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a.lit && a.s == "--" {
			return append(out, args[i+1:]...)
		}
		if a.lit && len(a.s) > 1 && strings.HasPrefix(a.s, "-") {
			if len(a.s) == 2 && strings.ContainsRune(valued, rune(a.s[1])) {
				i++
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

// flagValues collects the values of a flag given as "-e X", "--name X" or
// "--name=X". It returns the values and the arguments that are left.
func flagValues(args []wv, names []string) (vals, rest []wv) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		matched := false
		for _, n := range names {
			if a.lit && a.s == n && i+1 < len(args) {
				vals = append(vals, args[i+1])
				i++
				matched = true
				break
			}
			if strings.HasPrefix(n, "--") && strings.HasPrefix(a.s, n+"=") {
				v := a
				v.s = a.s[len(n)+1:]
				vals = append(vals, v)
				matched = true
				break
			}
		}
		if !matched {
			rest = append(rest, a)
		}
	}
	return vals, rest
}

func (sc *scope) nested(src string) {
	g := sc.g
	g.depth++
	g.analyze(src)
	g.depth--
}

func (sc *scope) shell(args []wv, c ctx) {
	g := sc.g
	for i, a := range args {
		if !a.lit {
			g.dyn(ask, "shell invoked with computed arguments")
			return
		}
		if a.s == "--" {
			continue
		}
		if strings.HasPrefix(a.s, "-") && !strings.HasPrefix(a.s, "--") {
			if strings.Contains(a.s, "c") {
				if i+1 >= len(args) {
					return
				}
				if !args[i+1].lit {
					g.dyn(ask, "shell -c with a computed script")
					return
				}
				sc.nested(args[i+1].s)
				return
			}
			if a.s == "-s" {
				break
			}
			continue
		}
		if strings.HasPrefix(a.s, "--") {
			continue
		}
		sc.scanFile(a)
		return
	}
	switch {
	case c.hdoc != nil:
		if !c.hdoc.lit {
			g.dyn(ask, "shell fed a here-document with expansions")
			return
		}
		sc.nested(c.hdoc.s)
	case c.piped:
		g.hard(deny, "piping generated text into a shell hides what runs")
	}
}

// scanFile analyses a shell script that is about to run. Findings are
// reported as "ask": the script's variables and loops are not followed.
func (sc *scope) scanFile(path wv) {
	g := sc.g
	if !path.lit || path.glob >= 0 || path.s == "" {
		return
	}
	p := path.s
	if !filepath.IsAbs(p) {
		p = filepath.Join(g.cfg.cwd, p)
	}
	info, err := os.Stat(p)
	if err != nil || info.IsDir() || info.Size() > 512<<10 {
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	sub := &guard{cfg: g.cfg, lenient: true, depth: g.depth + 1}
	sub.analyze(string(data))
	for _, r := range sub.reasons {
		g.note(ask, fmt.Sprintf("script %s: %s", filepath.Base(p), r))
	}
}

var riskyCode = regexp.MustCompile(`(?i)rmtree|os\.remove|os\.unlink|\.unlink\(|unlinkSync|rmdir|rmSync|fs\.rm\b|removeAll|FileUtils\.rm|\brm\s+-|\bgcloud\b|\bkubectl\b|\bgsutil\b|\bbq\s|\bcockroach\b|\bpsql\b|\bdrop\s+(table|database|schema|index|view)\b|\btruncate\s+table\b|\bdelete\s+from\b|do shell script|diskutil|tmutil`)

// fileOpens finds a file name passed to a call that reads it. load_dotenv is
// not among them: it loads the values into the process without showing them.
var fileOpens = regexp.MustCompile(`(?:\bopen|\bPath|read_text|read_bytes|readFileSync|readFile|File\.read|IO\.read|dotenv_values|file_get_contents|createReadStream)\s*\(\s*[fbr]?['"]([^'"]+)['"]`)

var opaqueLoads = regexp.MustCompile(`(?:load_dotenv|dotenv\.config|Dotenv\.load)\s*\([^)]*\)`)

var fileNames = regexp.MustCompile(`[A-Za-z0-9_./~-]*\.[A-Za-z0-9_.-]+`)

func (sc *scope) scanCode(name string, code wv) {
	g := sc.g
	if !code.lit && len(strings.TrimSpace(code.s)) < 20 {
		g.dyn(ask, "%s runs code built at run time", name)
		return
	}
	for _, m := range fileOpens.FindAllStringSubmatch(code.s, -1) {
		if g.cfg.isSecretFile(m[1]) {
			g.hard(deny, "inline %s code opens the secret file %s; load it into a process instead (--env-file, load_dotenv)", name, filepath.Base(m[1]))
			return
		}
	}
	// Loading a secret file into the process is the sanctioned way to use it.
	mentions := opaqueLoads.ReplaceAllString(code.s, "")
	for _, m := range fileNames.FindAllString(mentions, -1) {
		if g.cfg.isSecretFile(m) {
			g.hard(ask, "inline %s code names the secret file %s; check it does not print it", name, filepath.Base(m))
			return
		}
	}
	if m := riskyCode.FindString(code.s); m != "" {
		g.hard(ask, "inline %s code contains %q; review it", name, strings.TrimSpace(m))
	}
}

func (sc *scope) interpreter(name string, codeFlags []string, args []wv, c ctx) {
	g := sc.g
	codes, rest := flagValues(args, codeFlags)
	if len(codes) > 0 {
		for _, code := range codes {
			sc.scanCode(name, code)
		}
		return
	}
	hasFile := false
	for _, a := range rest {
		if a.s == "-m" {
			hasFile = true
		}
		if !strings.HasPrefix(a.s, "-") {
			hasFile = true
		}
	}
	if hasFile {
		return
	}
	switch {
	case c.hdoc != nil:
		sc.scanCode(name, *c.hdoc)
	case c.piped:
		g.dyn(ask, "%s reads its program from a pipe", name)
	}
}

const (
	pathOK = iota
	pathOutside
	pathDynamic
)

func hasDotDot(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// realpath resolves symlinks in every directory component that exists; the
// last component is kept as written (rm removes the link, not its target).
func realpath(p string) string {
	p = filepath.Clean(p)
	if p == "/" {
		return p
	}
	dir, last := filepath.Dir(p), filepath.Base(p)
	cur := dir
	var tail []string
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			cur = r
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		cur = parent
	}
	return filepath.Join(append(append([]string{cur}, tail...), last)...)
}

func under(p, root string, inclusive bool) bool {
	if p == root {
		return inclusive
	}
	return strings.HasPrefix(p, strings.TrimRight(root, "/")+"/")
}

func (c config) inRoots(p string, inclusive bool) bool {
	for _, r := range c.roots {
		if under(p, r, inclusive && r == c.project) {
			return true
		}
	}
	return c.project != "" && under(p, c.project, inclusive)
}

// pathStatus decides whether a deletion target is acceptable. A relative
// path is checked against every directory the shell can be in at that point:
// the starting directory and each cd target.
func (sc *scope) pathStatus(v wv) int {
	if !v.lit || v.s == "" {
		return pathDynamic
	}
	if filepath.IsAbs(v.s) {
		return sc.pathStatusIn(v, "")
	}
	if sc.hasCd && !sc.cdSafe {
		return pathDynamic
	}
	worst := sc.pathStatusIn(v, sc.g.cfg.cwd)
	for _, d := range sc.cdDirs {
		if st := sc.pathStatusIn(v, d); st > worst {
			worst = st
		}
	}
	return worst
}

func (sc *scope) pathStatusIn(v wv, cwd string) int {
	cfg := sc.g.cfg
	s := v.s
	rel := !filepath.IsAbs(s)
	if v.glob >= 0 {
		prefix := s[:v.glob]
		if i := strings.LastIndex(prefix, "/"); i >= 0 {
			prefix = prefix[:i+1]
		} else {
			prefix = ""
		}
		if hasDotDot(s[len(prefix):]) {
			return pathDynamic
		}
		dir := prefix
		if dir == "" {
			dir = "."
		}
		if rel {
			dir = filepath.Join(cwd, dir)
		}
		// Everything a glob matches lies below dir, so dir itself must be
		// inside a root, not merely equal to one.
		if cfg.inRoots(realpath(filepath.Join(dir, "x")), false) && cfg.inRoots(realpath(dir), true) {
			return pathOK
		}
		return pathOutside
	}
	if rel {
		s = filepath.Join(cwd, s)
	}
	p := realpath(s)
	if p == cfg.project || !cfg.inRoots(p, false) {
		return pathOutside
	}
	return pathOK
}

var devSinks = regexp.MustCompile(`^/dev/(null|stdout|stderr|tty|fd/\d+)$`)

// clobber checks a file that is about to be overwritten. strict also refuses
// targets the guard cannot resolve.
func (sc *scope) clobber(what string, t wv, strict bool) {
	g := sc.g
	if g.cfg.disabled["delete"] {
		return
	}
	if t.lit && (devSinks.MatchString(t.s) || t.s == "-") {
		return
	}
	switch sc.pathStatus(t) {
	case pathOutside:
		g.hard(deny, "%s overwrites a file outside the allowed roots: %s", what, t.s)
	case pathDynamic:
		if strict {
			g.dyn(deny, "%s target is not a literal path", what)
		}
	}
}

func (sc *scope) remove(name string, args []wv, c ctx) {
	g := sc.g
	if g.cfg.disabled["delete"] {
		return
	}
	if c.dynTail {
		g.dyn(deny, "%s gets its targets at run time (xargs); list them literally", name)
		return
	}
	for _, t := range positionals(args, "") {
		switch sc.pathStatus(t) {
		case pathOutside:
			g.hard(deny, "%s target is outside the allowed roots: %s", name, t.s)
		case pathDynamic:
			g.dyn(deny, "%s target is not a literal path the guard can resolve: %q", name, t.s)
		}
	}
}

func (sc *scope) rsync(args []wv) {
	g := sc.g
	if g.cfg.disabled["delete"] {
		return
	}
	deletes, moves := false, false
	for _, a := range args {
		if strings.HasPrefix(a.s, "--del") {
			deletes = true
		}
		if a.s == "--remove-source-files" || a.s == "--remove-sent-files" {
			moves = true
		}
	}
	if !deletes && !moves {
		return
	}
	pos := positionals(args, "ef")
	if len(pos) == 0 {
		return
	}
	check := pos[len(pos)-1:]
	if moves {
		check = pos
	}
	for _, t := range check {
		if t.lit && strings.Contains(strings.SplitN(t.s, "/", 2)[0], ":") {
			g.hard(ask, "rsync deletes on a remote host: %s", t.s)
			continue
		}
		switch sc.pathStatus(t) {
		case pathOutside:
			g.hard(deny, "rsync --delete outside the allowed roots: %s", t.s)
		case pathDynamic:
			g.dyn(deny, "rsync --delete with a target the guard cannot resolve")
		}
	}
}

func (sc *scope) find(args []wv, c ctx) {
	g := sc.g
	if g.cfg.disabled["delete"] {
		return
	}
	i, follow := 0, false
	for i < len(args) && args[i].lit && len(args[i].s) == 2 && strings.ContainsAny(args[i].s[1:], "HLPEXdsx") && args[i].s[0] == '-' {
		if args[i].s == "-L" {
			follow = true
		}
		i++
	}
	var roots []wv
	for i < len(args) {
		a := args[i]
		if a.lit && (strings.HasPrefix(a.s, "-") || a.s == "(" || a.s == "!") {
			break
		}
		roots = append(roots, a)
		i++
	}
	deletes := false
	for ; i < len(args); i++ {
		switch args[i].s {
		case "-follow":
			follow = true
		case "-delete":
			deletes = true
		case "-exec", "-execdir", "-ok", "-okdir":
			j := i + 1
			for j < len(args) && args[j].s != ";" && args[j].s != "+" {
				j++
			}
			sub := args[i+1 : j]
			if len(sub) > 0 && sub[0].lit && rmLike[filepath.Base(sub[0].s)] {
				deletes = true
			} else if len(sub) > 0 {
				sc.cmd(sub, ctx{env: map[string]bool{}, dynTail: true, remote: c.remote})
			}
			i = j
		}
	}
	if !deletes {
		return
	}
	if follow {
		g.hard(deny, "find that follows symlinks and deletes can leave the allowed roots")
		return
	}
	if len(roots) == 0 {
		roots = []wv{{s: ".", lit: true, glob: -1}}
	}
	for _, r := range roots {
		// The search root's contents are deleted: treat it like "root/*".
		t := r
		if t.lit && t.glob < 0 {
			t.s = strings.TrimRight(t.s, "/") + "/*"
			t.glob = len(t.s) - 1
		}
		switch sc.pathStatus(t) {
		case pathOutside:
			g.hard(deny, "find deletes below a path outside the allowed roots: %s", r.s)
		case pathDynamic:
			g.dyn(deny, "find deletes below a path the guard cannot resolve")
		}
	}
}
