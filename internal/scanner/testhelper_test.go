package scanner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func makeRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "hooks"), 0o755); err != nil {
		t.Fatalf("makeRepo: create .git/hooks: %v", err)
	}
	writeFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/main\n")
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("writeFile: mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
}

func writeExec(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("writeExec: mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("writeExec %s: %v", path, err)
	}
}

func writeGitConfig(t *testing.T, repoPath, content string) {
	t.Helper()
	writeFile(t, filepath.Join(repoPath, ".git", "config"), content)
}

// assertFinding fails unless at least one finding has module==module and
// Message contains msgSubstr.
func assertFinding(t *testing.T, findings []scanner.Finding, module, msgSubstr string) {
	t.Helper()
	for _, f := range findings {
		if f.Module == module && strings.Contains(f.Message, msgSubstr) {
			return
		}
	}
	t.Errorf("no finding in module %q with message containing %q; got: %v",
		module, msgSubstr, findings)
}

// assertNoFindings fails if any findings were produced.
func assertNoFindings(t *testing.T, findings []scanner.Finding) {
	t.Helper()
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

// assertSeverity fails unless a finding whose Message contains msgSubstr has
// the expected severity.
func assertSeverity(t *testing.T, findings []scanner.Finding, msgSubstr string, want scanner.Severity) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.Message, msgSubstr) {
			if f.Severity != want {
				t.Errorf("finding %q: severity = %v, want %v", msgSubstr, f.Severity, want)
			}
			return
		}
	}
	t.Errorf("no finding with message containing %q", msgSubstr)
}
