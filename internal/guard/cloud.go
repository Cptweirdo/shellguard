package guard

import (
	"regexp"
	"strings"
)

var (
	gcloudDestroy = set("delete", "destroy", "rm", "purge", "set-iam-policy", "remove-iam-policy-binding", "abandon-instances", "delete-instances")
	gcloudRead    = set("list", "describe", "get", "get-value", "read", "logs", "tail", "get-iam-policy",
		"ls", "cat", "du", "hash", "show", "lookup", "search", "print-settings", "get-server-config", "get-ancestors")
	gcloudTopRead = set("version", "info", "help", "topic", "cheat-sheet")
)

// tokens returns the literal non-flag arguments. firstDyn is the number of
// tokens seen before the first argument only the shell can expand (-1: none).
func tokens(args []wv) (toks []string, firstDyn int) {
	firstDyn = -1
	for _, a := range args {
		if !a.lit {
			if firstDyn < 0 {
				firstDyn = len(toks)
			}
			continue
		}
		if strings.HasPrefix(a.s, "-") {
			continue
		}
		toks = append(toks, a.s)
	}
	return toks, firstDyn
}

func hasFlagPrefix(args []wv, prefixes ...string) bool {
	for _, a := range args {
		for _, p := range prefixes {
			if a.s == p || strings.HasPrefix(a.s, p+"=") {
				return true
			}
		}
	}
	return false
}

func (sc *scope) gcloud(args []wv, c ctx) {
	g := sc.g
	if g.cfg.disabled["cloud"] {
		return
	}
	toks, firstDyn := tokens(args)
	for len(toks) > 0 && (toks[0] == "beta" || toks[0] == "alpha") {
		toks = toks[1:]
		if firstDyn > 0 {
			firstDyn--
		}
	}
	if len(toks) == 0 {
		return
	}
	for _, t := range toks[1:] {
		if gcloudDestroy[t] {
			g.hard(deny, "gcloud %s %s is destructive; run it in your own terminal", toks[0], t)
			return
		}
	}
	if has(args, "secrets") && has(args, "access") {
		g.hard(deny, "gcloud secrets versions access prints a secret value")
		return
	}
	if toks[0] == "auth" && (has(args, "print-access-token", "print-identity-token", "print-refresh-token")) {
		g.dyn(ask, "gcloud auth print-*-token prints a credential")
		return
	}
	read := gcloudTopRead[toks[0]]
	verb, verbAt := toks[0], 0
	for i, t := range toks[1:] {
		isRead := gcloudRead[t] || strings.HasPrefix(t, "list-") || strings.HasPrefix(t, "describe-")
		if isRead {
			read, verb, verbAt = true, t, i+1
			break
		}
		if looksLikeVerb(t) {
			verb = t
			break
		}
	}
	// A computed value after a read verb (an id, a --project) cannot turn the
	// call into a write; one before it could be the verb itself.
	dynamic := firstDyn >= 0 && (!read || firstDyn <= verbAt)
	switch {
	case dynamic:
		g.dyn(ask, "gcloud with arguments computed at run time")
	case !read:
		g.hard(ask, "gcloud %s %s is not a known read-only command", toks[0], verb)
	case hasFlagPrefix(args, "--impersonate-service-account", "--account"):
		g.hard(ask, "gcloud run under another identity")
	case c.envPrefix("CLOUDSDK_"):
		g.hard(ask, "gcloud with a CLOUDSDK_* override")
	}
}

var verbish = regexp.MustCompile(`^(create|update|patch|deploy|set|add|remove|enable|disable|apply|import|export|replace|resize|rollback|restart|start|stop|scale|submit|ssh|scp|cp|mv|run|execute|call|publish|pull|ack|seek|login|revoke|activate|reset|rotate|undelete|restore|get-credentials|move|migrate|upgrade|install|init|configure|clone|promote|failover|cancel|drain|rsync|sign-url|copy-files)($|-)`)

func looksLikeVerb(t string) bool { return verbish.MatchString(t) }

var kubectlValued = set("-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-s", "--server",
	"--as", "--as-group", "--token", "--request-timeout", "-l", "--selector", "-o", "--output", "-f", "--filename",
	"-c", "--container", "--field-selector", "--tail", "--since", "--since-time", "--sort-by", "-L", "--label-columns")

var (
	kubectlRead  = set("get", "describe", "logs", "top", "version", "api-resources", "api-versions", "explain", "cluster-info", "diff", "events", "wait", "kustomize", "help", "completion")
	secretRes    = regexp.MustCompile(`(?i)(^|,)secrets?(\.|/|,|$)`)
	valueOutputs = regexp.MustCompile(`(?i)^(yaml|json|jsonpath|go-template|custom-columns|template)`)
)

func (sc *scope) kubectl(args []wv, c ctx) {
	g := sc.g
	if g.cfg.disabled["cloud"] {
		return
	}
	// "kubectl exec ... -- cmd": check cmd as a command that runs remotely.
	for i, a := range args {
		if a.lit && a.s == "--" {
			sub := args[i+1:]
			args = args[:i]
			if len(sub) > 0 {
				sc.cmd(sub, ctx{env: map[string]bool{}, remote: true, hdoc: c.hdoc, piped: c.piped})
			}
			break
		}
	}
	var pos []wv
	var output string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !a.lit {
			g.dyn(ask, "kubectl with arguments computed at run time")
			return
		}
		if strings.HasPrefix(a.s, "-") {
			name, val, hasEq := strings.Cut(a.s, "=")
			if !hasEq && kubectlValued[name] && i+1 < len(args) {
				val = args[i+1].s
				i++
			} else if !hasEq && strings.HasPrefix(a.s, "-o") && len(a.s) > 2 {
				name, val = "-o", a.s[2:]
			}
			if name == "-o" || name == "--output" {
				output = val
			}
			continue
		}
		pos = append(pos, a)
	}
	if len(pos) == 0 {
		return
	}
	verb := pos[0].s
	rest := pos[1:]
	switch {
	case verb == "delete":
		g.hard(deny, "kubectl delete is destructive; run it in your own terminal")
	case verb == "replace" && hasFlagPrefix(args, "--force"):
		g.hard(deny, "kubectl replace --force deletes and recreates the resource")
	case verb == "get":
		for _, r := range rest {
			if secretRes.MatchString(r.s) && valueOutputs.MatchString(output) {
				g.hard(deny, "kubectl get secret -o %s prints secret values", output)
				return
			}
		}
	case kubectlRead[verb]:
	case verb == "config":
		if !(has(rest, "get-contexts", "current-context", "get-clusters", "get-users") || (has(rest, "view") && !hasFlagPrefix(args, "--raw"))) {
			g.hard(ask, "kubectl config changes or reveals cluster credentials")
		}
	case verb == "rollout" && has(rest, "status", "history"):
	case verb == "auth" && has(rest, "can-i", "whoami"):
	default:
		g.hard(ask, "kubectl %s is not a read-only command", verb)
	}
	if hasFlagPrefix(args, "--as", "--as-group", "--token") {
		g.hard(ask, "kubectl run under another identity")
	}
	if c.envPrefix("KUBECONFIG") {
		g.hard(ask, "kubectl with a KUBECONFIG override")
	}
}

func (sc *scope) gsutil(args []wv, c ctx) {
	g := sc.g
	if g.cfg.disabled["cloud"] {
		return
	}
	_, rest := flagValues(args, []string{"-o", "-h", "-i", "-u"})
	pos := positionals(rest, "")
	if len(pos) == 0 {
		return
	}
	switch v := pos[0].s; v {
	case "ls", "cat", "du", "stat", "version", "help", "hash":
	case "rm", "rb":
		g.hard(deny, "gsutil %s deletes bucket data", v)
	case "rsync":
		if hasFlagLetter(args, "d") {
			g.hard(deny, "gsutil rsync -d deletes objects at the destination")
		} else {
			g.hard(ask, "gsutil rsync writes bucket data")
		}
	default:
		g.hard(ask, "gsutil %s is not a read-only command", v)
	}
}

func (sc *scope) helm(args []wv) {
	g := sc.g
	if g.cfg.disabled["cloud"] {
		return
	}
	pos := positionals(args, "n")
	if len(pos) == 0 {
		return
	}
	switch v := pos[0].s; v {
	case "list", "ls", "status", "get", "history", "show", "template", "lint", "version", "search", "env", "help", "diff", "dependency", "completion":
	case "uninstall", "delete", "del", "un":
		g.hard(deny, "helm %s removes a release", v)
	case "repo":
		if !has(pos[1:], "list", "ls") {
			g.hard(ask, "helm repo changes repositories")
		}
	default:
		g.hard(ask, "helm %s is not a read-only command", v)
	}
}

func (sc *scope) terraform(name string, args []wv) {
	g := sc.g
	if g.cfg.disabled["cloud"] {
		return
	}
	var pos []wv
	for _, a := range args {
		if !strings.HasPrefix(a.s, "-") {
			pos = append(pos, a)
		}
	}
	if len(pos) == 0 {
		return
	}
	switch v := pos[0].s; v {
	case "plan", "show", "validate", "fmt", "version", "output", "providers", "graph", "init", "get", "console", "test", "help":
		if v == "plan" && hasFlagPrefix(args, "-out", "--out") {
			return
		}
	case "destroy":
		g.hard(deny, "%s destroy is destructive", name)
	case "apply":
		if hasFlagPrefix(args, "-destroy", "--destroy", "-auto-approve", "--auto-approve") {
			g.hard(deny, "%s apply with -auto-approve or -destroy skips the review", name)
		} else {
			g.hard(ask, "%s apply changes infrastructure", name)
		}
	case "state":
		if !has(pos[1:], "list", "show", "pull") {
			g.hard(ask, "%s state changes the state file", name)
		}
	default:
		g.hard(ask, "%s %s is not a read-only command", name, v)
	}
}

var (
	awsDestroy = regexp.MustCompile(`^(delete|terminate|remove|deregister|purge|destroy|batch-delete|disable-key|schedule-key-deletion|empty)(-|$)`)
	awsRead    = regexp.MustCompile(`^(describe|list|get|head|show|search|lookup|view|check|validate|estimate|wait|ls|help|presign)(-|$)`)
)

func (sc *scope) aws(args []wv, c ctx) {
	g := sc.g
	if g.cfg.disabled["cloud"] {
		return
	}
	_, rest := flagValues(args, []string{"--profile", "--region", "--output", "--endpoint-url", "--query", "--color", "--cli-read-timeout"})
	toks, firstDyn := tokens(rest)
	dynamic := firstDyn >= 0 && firstDyn <= 1
	if len(toks) == 0 {
		return
	}
	if len(toks) == 1 {
		if toks[0] != "help" {
			g.hard(ask, "aws %s is not a known read-only command", toks[0])
		}
		return
	}
	svc, op := toks[0], toks[1]
	switch {
	case svc == "secretsmanager" && (op == "get-secret-value" || op == "batch-get-secret-value"),
		svc == "ssm" && strings.HasPrefix(op, "get-parameter") && hasFlagPrefix(args, "--with-decryption"):
		g.hard(deny, "aws %s %s prints a secret value", svc, op)
	case svc == "s3" && (op == "rm" || op == "rb"), awsDestroy.MatchString(op):
		g.hard(deny, "aws %s %s is destructive; run it in your own terminal", svc, op)
	case svc == "s3" && op == "sync" && hasFlagPrefix(args, "--delete"):
		g.hard(deny, "aws s3 sync --delete removes objects at the destination")
	case dynamic:
		g.dyn(ask, "aws with arguments computed at run time")
	case svc == "sts" || svc == "configure" && has(args, "list", "get", "list-profiles"):
	case awsRead.MatchString(op):
	default:
		g.hard(ask, "aws %s %s is not a known read-only command", svc, op)
	}
}
