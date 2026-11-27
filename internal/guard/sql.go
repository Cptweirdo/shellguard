package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	sqlRead = iota
	sqlUnknown
	sqlWrite
)

var (
	sqlWriteWord = regexp.MustCompile(`(?i)\b(insert|update|upsert|delete|drop|truncate|alter|create|grant|revoke|merge|call|execute|copy|import|restore|backup|comment\s+on|reassign|cancel|pause|resume|export\s+data|load\s+data)\b`)
	sqlReadStart = regexp.MustCompile(`(?i)^(select|show|with|values|table|explain|use)\b`)
	sqlAnalyze   = regexp.MustCompile(`(?i)^explain\s*(\([^)]*\banalyze\b[^)]*\)|analyze\b)`)
	sqlInto      = regexp.MustCompile(`(?i)\binto\b`)
)

// stripSQL removes comments and the contents of string literals, so that
// keywords inside them do not count.
func stripSQL(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case strings.HasPrefix(s[i:], "--"):
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case strings.HasPrefix(s[i:], "/*"):
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				i = len(s)
			} else {
				i += end + 3
			}
			b.WriteByte(' ')
		case s[i] == '\'' || s[i] == '"' || s[i] == '`':
			q := s[i]
			i++
			for i < len(s) {
				if s[i] == '\\' && q != '"' && i+1 < len(s) {
					i += 2
					continue
				}
				if s[i] == q {
					if i+1 < len(s) && s[i+1] == q {
						i += 2
						continue
					}
					break
				}
				i++
			}
			b.WriteString(" '' ")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// classifySQL sorts a batch of statements: read-only, write, or unknown.
// It is a keyword check, deliberately biased towards "write".
func classifySQL(sql string) (int, string) {
	clean := stripSQL(sql)
	worst, why := sqlRead, ""
	n := 0
	for _, st := range strings.Split(clean, ";") {
		st = strings.TrimSpace(st)
		if st == "" || strings.HasPrefix(st, `\`) {
			continue
		}
		n++
		kind, w := sqlRead, ""
		switch {
		case sqlWriteWord.MatchString(st):
			kind, w = sqlWrite, strings.ToUpper(sqlWriteWord.FindString(st))
		case sqlAnalyze.MatchString(st):
			kind, w = sqlWrite, "EXPLAIN ANALYZE (executes the statement)"
		case !sqlReadStart.MatchString(st):
			kind, w = sqlUnknown, firstWord(st)
		case sqlInto.MatchString(st):
			kind, w = sqlUnknown, "SELECT ... INTO"
		}
		if kind > worst {
			worst, why = kind, w
		}
	}
	if n == 0 {
		return sqlUnknown, "no statement"
	}
	return worst, why
}

func firstWord(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return strings.ToUpper(f[0])
}

// judgeSQL records the verdict for SQL headed to a production database.
func (sc *scope) judgeSQL(where string, sql wv) {
	g := sc.g
	if !sql.lit {
		g.dyn(ask, "%s: the SQL contains shell expansions and cannot be checked", where)
		return
	}
	switch kind, why := classifySQL(sql.s); kind {
	case sqlWrite:
		g.hard(deny, "%s: %s is not read-only; run writes in your own terminal", where, why)
	case sqlUnknown:
		g.hard(ask, "%s: cannot tell that %q is read-only", where, why)
	}
}

func (sc *scope) judgeSQLFile(where string, path wv) {
	g := sc.g
	if !path.lit {
		g.dyn(deny, "%s: SQL file path is computed at run time", where)
		return
	}
	p := path.s
	if !filepath.IsAbs(p) {
		p = filepath.Join(g.cfg.cwd, p)
	}
	info, err := os.Stat(p)
	if err != nil || info.Size() > 1<<20 {
		g.dyn(deny, "%s: cannot read SQL file %s to check it", where, path.s)
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		g.dyn(deny, "%s: cannot read SQL file %s to check it", where, path.s)
		return
	}
	sc.judgeSQL(where+" (file "+filepath.Base(p)+")", wv{s: string(data), lit: true, glob: -1})
}

// judgeStdinSQL handles a client that reads its statements from stdin.
func (sc *scope) judgeStdinSQL(where string, c ctx) {
	g := sc.g
	switch {
	case c.hdoc != nil:
		sc.judgeSQL(where, *c.hdoc)
	case c.piped:
		g.hard(ask, "%s: the SQL arrives through a pipe and cannot be checked", where)
	default:
		g.hard(ask, "%s: interactive SQL shell on a non-local database", where)
	}
}

var (
	urlHost  = regexp.MustCompile(`(?:@|//)([A-Za-z0-9_.\-\[\]:]*?)(?::\d+)?(?:[/?]|$)`)
	kvHost   = regexp.MustCompile(`\bhost=([^\s&]+)`)
	certHint = regexp.MustCompile(`certs-dir|sslcert|sslkey|sslrootcert|ssl-cert|ssl-key`)
)

func localHost(h string) bool {
	h = strings.Trim(h, "[]")
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[:i], ":") {
		h = h[:i]
	}
	return h == "" || h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// isLocalDB reports whether a cockroach/psql invocation targets the local
// stack. The production bridge also listens on localhost but needs the root
// client certificates, so any certificate argument means production.
func isLocalDB(args []wv, c ctx, noLocal bool) bool {
	if noLocal || c.remote || c.envPrefix("PG", "COCKROACH_", "MYSQL_") {
		return false
	}
	hosts, rest := flagValues(args, []string{"--host", "-h", "--url"})
	for _, a := range args {
		// joined short form: -hdb.example.com
		if a.lit && len(a.s) > 2 && strings.HasPrefix(a.s, "-h") && !strings.HasPrefix(a.s, "--") {
			h := a
			h.s = a.s[2:]
			hosts = append(hosts, h)
		}
	}
	for _, a := range args {
		if !a.lit || certHint.MatchString(a.s) {
			return false
		}
	}
	for _, h := range hosts {
		if strings.Contains(h.s, "://") {
			rest = append(rest, h)
			continue
		}
		if !localHost(h.s) {
			return false
		}
	}
	for _, a := range rest {
		if strings.Contains(a.s, "://") {
			m := urlHost.FindAllStringSubmatch(a.s, -1)
			if len(m) == 0 || !localHost(m[len(m)-1][1]) {
				return false
			}
		}
		if m := kvHost.FindStringSubmatch(a.s); m != nil && !localHost(m[1]) {
			return false
		}
	}
	return true
}

func (sc *scope) sqlClient(name string, args []wv, c ctx, execFlags, fileFlags []string) {
	if sc.g.cfg.disabled["sql"] {
		return
	}
	if isLocalDB(args, c, sc.g.cfg.noLocalDB) {
		return
	}
	where := name + " (not the local stack)"
	stmts, rest := flagValues(args, execFlags)
	files, _ := flagValues(rest, fileFlags)
	for _, s := range stmts {
		sc.judgeSQL(where, s)
	}
	for _, f := range files {
		sc.judgeSQLFile(where, f)
	}
	if len(stmts) == 0 && len(files) == 0 {
		sc.judgeStdinSQL(where, c)
	}
}

func (sc *scope) bq(args []wv, c ctx) {
	g := sc.g
	_, rest := flagValues(args, []string{"--project_id", "--location", "--dataset_id", "--format", "--apilog", "--credential_file"})
	pos := positionals(rest, "")
	if len(pos) == 0 {
		return
	}
	if !pos[0].lit {
		g.dyn(ask, "bq with a computed subcommand")
		return
	}
	switch pos[0].s {
	case "ls", "show", "head", "version", "help":
	case "rm":
		g.hard(deny, "bq rm deletes BigQuery data")
	case "query":
		if g.cfg.disabled["sql"] {
			return
		}
		for _, a := range args {
			if a.s == "--dry_run" || a.s == "--dry_run=true" {
				return
			}
		}
		if len(pos) > 1 {
			sc.judgeSQL("bq query", pos[len(pos)-1])
		} else {
			sc.judgeStdinSQL("bq query", c)
		}
	default:
		g.hard(ask, "bq %s changes BigQuery state", pos[0].s)
	}
}
