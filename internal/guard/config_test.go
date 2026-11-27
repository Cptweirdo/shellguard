package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeJSONFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A project file may add rules but never widen the deletion roots.
func TestProjectConfigIsAdditiveOnly(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(t.TempDir(), "work", "proj")
	writeJSONFile(t, ProjectConfigPath(proj), `{
		"roots": ["/"],
		"disable": ["delete"],
		"rules": [{"match": ["make", "deploy"], "verdict": "deny"}]
	}`)
	t.Setenv("HOME", home)
	t.Setenv("SHELLGUARD_CONFIG", filepath.Join(home, "none.json"))
	t.Setenv("CLAUDE_PROJECT_DIR", proj)
	t.Setenv("SHELLGUARD_ROOTS", "")

	if v, _ := Check(proj, "make deploy"); v != Deny {
		t.Errorf("project rule not applied: %v", v)
	}
	if v, _ := Check(proj, "rm -rf /etc/x"); v != Deny {
		t.Errorf("project file widened the roots or disabled deletes: %v", v)
	}
}

func TestUserConfigRootsAndProblems(t *testing.T) {
	home := t.TempDir()
	extra := filepath.Join(t.TempDir(), "scratch", "area")
	cfg := filepath.Join(home, "sg.json")
	t.Setenv("HOME", home)
	t.Setenv("SHELLGUARD_CONFIG", cfg)
	t.Setenv("CLAUDE_PROJECT_DIR", "")
	t.Setenv("SHELLGUARD_ROOTS", "")

	writeJSONFile(t, cfg, `{"roots": ["`+extra+`"]}`)
	if v, r := Check(home, "rm -rf "+extra+"/x"); v != Allow {
		t.Errorf("user root not honoured: %v %s", v, r)
	}

	// The home directory and the filesystem root are refused as roots, and
	// the refusal escalates every command until the file is fixed.
	writeJSONFile(t, cfg, `{"roots": ["~", "/"]}`)
	t.Setenv("TMPDIR", "/nonexistent-tmp") // t.TempDir() lies below the real one
	if p := Describe(home); len(p.Problems) != 2 {
		t.Errorf("want 2 problems for ~ and /, got %q", p.Problems)
	}
	if v, _ := Check(home, "rm -rf "+home+"/x"); v != Deny {
		t.Errorf("home accepted as a root: %v", v)
	}
}

func TestBrokenConfigAsks(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, "sg.json")
	writeJSONFile(t, cfg, `{"rules": [{"match": ["x"], "verdict": "maybe"}]}`)
	t.Setenv("HOME", home)
	t.Setenv("SHELLGUARD_CONFIG", cfg)
	t.Setenv("CLAUDE_PROJECT_DIR", "")
	v, r := Check(home, "ls")
	if v != Ask || !strings.Contains(r, "configuration problem") {
		t.Errorf("broken config must escalate, got %v %s", v, r)
	}
}

func TestWorktreesAreRoots(t *testing.T) {
	base := filepath.Join(t.TempDir(), "w", "src")
	main := filepath.Join(base, "app")
	wt := filepath.Join(base, "app-feature")
	writeJSONFile(t, filepath.Join(main, ".git", "worktrees", "app-feature", "gitdir"), filepath.Join(wt, ".git")+"\n")
	writeJSONFile(t, filepath.Join(wt, ".git"), "gitdir: "+filepath.Join(main, ".git", "worktrees", "app-feature")+"\n")

	for _, proj := range []string{main, wt} {
		got := map[string]bool{}
		for _, r := range worktrees(proj) {
			got[r] = true
		}
		other := wt
		if proj == wt {
			other = main
		}
		if !got[realpath(other)] {
			t.Errorf("from %s: worktree %s missing in %v", proj, other, got)
		}
	}
}

func TestNoLocalDatabase(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(t.TempDir(), "work", "proj")
	t.Setenv("HOME", home)
	t.Setenv("SHELLGUARD_CONFIG", filepath.Join(home, "none.json"))
	t.Setenv("CLAUDE_PROJECT_DIR", proj)
	cmd := `mysql -h 127.0.0.1 -e 'drop table t'`
	if v, _ := Check(proj, cmd); v != Allow {
		t.Fatalf("localhost should be exempt by default, got %v", v)
	}
	writeJSONFile(t, ProjectConfigPath(proj), `{"no_local_database": true}`)
	if v, _ := Check(proj, cmd); v != Deny {
		t.Errorf("no_local_database not honoured: %v", v)
	}
}
