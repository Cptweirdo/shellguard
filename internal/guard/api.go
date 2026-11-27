// Package guard decides whether a shell command may run unattended.
//
// It parses the command with a real shell parser, walks every simple command
// in it and reports the ones that can do irreversible damage: deletions
// outside the allowed directories, write statements to non-local databases,
// destructive cloud CLI calls and commands that reveal secrets.
//
// The package never writes, never starts a program and never opens the
// network.
package guard

// Verdict is the guard's answer for one command.
type Verdict int

const (
	// Allow means no objection: the caller's normal flow continues.
	Allow Verdict = iota
	// Ask means a human should confirm the command.
	Ask
	// Deny means the command must not run unattended.
	Deny
)

func (v Verdict) String() string {
	switch v {
	case Ask:
		return "ask"
	case Deny:
		return "deny"
	}
	return "allow"
}

// Check judges one shell command as run from cwd. The policy comes from the
// environment (CLAUDE_PROJECT_DIR, TMPDIR, SHELLGUARD_ROOTS) and from the
// user and project configuration files.
func Check(cwd, command string) (Verdict, string) {
	level, reason := newGuard(configFromEnv(cwd)).check(command)
	return Verdict(level), reason
}

// Policy describes the resolved policy for diagnostics.
type Policy struct {
	Roots       []string
	Project     string
	Rules       int
	SQL         int
	SecretFiles []string
	Problems    []string
}

// Describe returns the policy Check would apply from cwd.
func Describe(cwd string) Policy {
	c := configFromEnv(cwd)
	return Policy{Roots: c.roots, Project: c.project, Rules: len(c.rules), SQL: len(c.sql),
		SecretFiles: c.secretFiles, Problems: c.problems}
}
