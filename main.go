// shellguard is a guard for shell commands run by a coding agent.
//
//	shellguard hook              Claude Code PreToolUse hook (JSON on stdin)
//	shellguard check 'command'   print the verdict for a command; runs nothing
//	shellguard policy            show the roots and rules in effect here
//	shellguard init              write starter files into the current project
//	shellguard settings          print (or --write) recommended user settings
//	shellguard version
package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/Cptweirdo/shellguard/internal/guard"
)

//go:embed templates
var templates embed.FS

func main() {
	args := os.Args[1:]
	cmd := "hook"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "hook":
		hook()
	case "check":
		check(args)
	case "policy":
		policy()
	case "init":
		initProject(args)
	case "settings":
		settings(args)
	case "version", "--version", "-v":
		fmt.Println(version())
	case "help", "--help", "-h":
		usage(os.Stdout)
	default:
		usage(os.Stderr)
		os.Exit(64)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `shellguard — stops destructive shell commands before a coding agent runs them

  shellguard hook               Claude Code PreToolUse hook: reads the hook JSON on stdin
  shellguard check 'command'    print the verdict for a command (nothing is executed)
  shellguard policy             show the roots, rules and config files in effect here
  shellguard init [--force]     write .claude/shellguard.json and CLAUDE.md starters
  shellguard settings [--write] [--hook]
                                recommended ~/.claude/settings.json additions
  shellguard version

Config: ~/.claude/shellguard.json (user) and <project>/.claude/shellguard.json.
`)
}

func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

type hookInput struct {
	ToolName  string `json:"tool_name"`
	Cwd       string `json:"cwd"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

// hook is the PreToolUse entry point. Silence means no objection. Any failure
// of the guard itself exits 2, which blocks the tool call.
func hook() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "shellguard: internal error, blocking the command: %v\n", r)
			os.Exit(2)
		}
	}()
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 8<<20))
	if err != nil {
		fmt.Fprintln(os.Stderr, "shellguard: cannot read the hook input, blocking the command")
		os.Exit(2)
	}
	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		fmt.Fprintln(os.Stderr, "shellguard: the hook input is not JSON, blocking the command")
		os.Exit(2)
	}
	if in.ToolName != "" && in.ToolName != "Bash" {
		return
	}
	if strings.TrimSpace(in.ToolInput.Command) == "" {
		return
	}
	verdict, reason := guard.Check(in.Cwd, in.ToolInput.Command)
	if verdict == guard.Allow {
		return
	}
	writeJSON(os.Stdout, map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       verdict.String(),
			"permissionDecisionReason": "shellguard: " + reason,
		},
	})
}

// check prints the verdict for a command without running it. Exit status:
// 0 allow, 1 ask, 2 deny.
func check(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: shellguard check 'command'   (use - to read it from stdin)")
		os.Exit(64)
	}
	command := strings.Join(args, " ")
	if command == "-" {
		b, _ := io.ReadAll(os.Stdin)
		command = string(b)
	}
	cwd, _ := os.Getwd()
	ensureProjectDir(cwd)
	verdict, reason := guard.Check(cwd, command)
	if reason != "" {
		fmt.Printf("%s: %s\n", verdict, reason)
	} else {
		fmt.Println(verdict)
	}
	os.Exit(int(verdict))
}

// ensureProjectDir lets the command-line tools behave like the hook when run
// by hand: without CLAUDE_PROJECT_DIR the nearest directory holding .claude
// or .git is taken as the project.
func ensureProjectDir(cwd string) {
	if os.Getenv("CLAUDE_PROJECT_DIR") != "" {
		return
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		for _, marker := range []string{".claude", ".git"} {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				os.Setenv("CLAUDE_PROJECT_DIR", dir)
				return
			}
		}
		if dir == filepath.Dir(dir) {
			return
		}
	}
}

func policy() {
	cwd, _ := os.Getwd()
	ensureProjectDir(cwd)
	home, _ := os.UserHomeDir()
	p := guard.Describe(cwd)
	fmt.Println("project:      ", orNone(p.Project))
	fmt.Println("user config:  ", exists(guard.UserConfigPath(home)))
	if p.Project != "" {
		fmt.Println("project config:", exists(guard.ProjectConfigPath(p.Project)))
	}
	fmt.Println("deletions are acceptable strictly below:")
	for _, r := range p.Roots {
		fmt.Println("  ", r)
	}
	if p.Project != "" {
		fmt.Println("  ", p.Project, "(the project)")
	}
	fmt.Printf("custom rules: %d, SQL wrappers: %d\n", p.Rules, p.SQL)
	fmt.Println("secret files: ", strings.Join(p.SecretFiles, " "))
	for _, pr := range p.Problems {
		fmt.Println("PROBLEM:", pr)
	}
	if len(p.Problems) > 0 {
		os.Exit(1)
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func exists(path string) string {
	if _, err := os.Stat(path); err != nil {
		return path + " (absent)"
	}
	return path
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "shellguard: "+format+"\n", a...)
	os.Exit(1)
}

// initProject writes the starter files. Existing files are never changed
// unless --force is given.
func initProject(args []string) {
	force := len(args) > 0 && args[0] == "--force"
	cwd, _ := os.Getwd()
	files := map[string]string{
		"templates/shellguard.json": filepath.Join(cwd, ".claude", "shellguard.json"),
		"templates/CLAUDE.md":       filepath.Join(cwd, "CLAUDE.md"),
	}
	for src, dst := range files {
		data, err := templates.ReadFile(src)
		if err != nil {
			die("%v", err)
		}
		if _, err := os.Stat(dst); err == nil && !force {
			fmt.Printf("kept     %s (exists; compare with `shellguard init --force` in a scratch copy, or see templates/ in the repository)\n", rel(cwd, dst))
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			die("%v", err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			die("%v", err)
		}
		fmt.Printf("wrote    %s\n", rel(cwd, dst))
	}
	fmt.Print(`
Next:
  1. Edit .claude/shellguard.json: name the commands of this project that reach
     production (deploys, database shells, publish steps).
  2. shellguard settings          # review the recommended user settings
  3. shellguard check 'rm -rf ~'  # try verdicts; nothing is executed
`)
}

func rel(base, p string) string {
	if r, err := filepath.Rel(base, p); err == nil {
		return r
	}
	return p
}

// settings prints the recommended additions to ~/.claude/settings.json, or
// merges them in with --write (a timestamped backup is kept).
func settings(args []string) {
	write, withHook := false, false
	for _, a := range args {
		switch a {
		case "--write":
			write = true
		case "--hook":
			withHook = true
		default:
			die("unknown option %s", a)
		}
	}
	data, err := templates.ReadFile("templates/settings.json")
	if err != nil {
		die("%v", err)
	}
	var add map[string]any
	if err := json.Unmarshal(data, &add); err != nil {
		die("template: %v", err)
	}
	if withHook {
		exe, err := os.Executable()
		if err != nil {
			die("%v", err)
		}
		add["hooks"] = map[string]any{"PreToolUse": []any{map[string]any{
			"matcher": "Bash",
			"hooks": []any{map[string]any{
				"type": "command", "command": fmt.Sprintf("%q hook", exe), "timeout": 10, "onFailure": "block",
			}},
		}}}
	}
	if !write {
		writeJSON(os.Stdout, add)
		fmt.Fprintln(os.Stderr, "\nNothing was changed. `shellguard settings --write` merges this into ~/.claude/settings.json and keeps a backup.")
		return
	}
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".claude", "settings.json")
	cur := map[string]any{}
	old, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(old, &cur); err != nil {
			die("%s is not valid JSON: %v", path, err)
		}
		backup := path + ".bak-" + time.Now().Format("20060102-150405")
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			die("%v", err)
		}
		fmt.Println("backup  ", backup)
	case !os.IsNotExist(err):
		die("%v", err)
	}
	merge(cur, add)
	var buf bytes.Buffer
	writeJSON(&buf, cur)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		die("%v", err)
	}
	fmt.Println("updated ", path)
}

// merge adds src into dst: objects merge key by key, lists become the union
// (existing entries first), and scalars already present in dst are kept.
func merge(dst, src map[string]any) {
	for k, v := range src {
		cur, ok := dst[k]
		if !ok {
			dst[k] = v
			continue
		}
		switch sv := v.(type) {
		case map[string]any:
			if dm, ok := cur.(map[string]any); ok {
				merge(dm, sv)
			}
		case []any:
			dl, ok := cur.([]any)
			if !ok {
				continue
			}
			seen := map[string]bool{}
			for _, e := range dl {
				b, _ := json.Marshal(e)
				seen[string(b)] = true
			}
			for _, e := range sv {
				b, _ := json.Marshal(e)
				if strings.Contains(string(b), "shellguard") && strings.Contains(fmt.Sprint(dl), "shellguard") {
					continue // a shellguard hook is already registered
				}
				if !seen[string(b)] {
					dl = append(dl, e)
				}
			}
			dst[k] = dl
		}
	}
}
