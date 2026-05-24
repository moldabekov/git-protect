package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func bareRepoScan(t *testing.T, repo string) []scanner.Finding {
	t.Helper()
	m := scanner.NewBareReposModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("bare-repos scan error: %v", err)
	}
	return findings
}

func TestBareRepos_CleanRepo_NoFindings(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, "src", "main.go"), "package main\n")
	writeFile(t, filepath.Join(repo, "docs", "README.md"), "# Project\n")
	findings := bareRepoScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in clean repo, got %d: %v", len(findings), findings)
	}
}

func TestBareRepos_RootGitDir_NotFlagged(t *testing.T) {
	repo := makeRepo(t)
	findings := bareRepoScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("root .git/ must not be flagged, got %d findings", len(findings))
	}
}

func TestBareRepos_EmbeddedGitDir_IsCritical(t *testing.T) {
	repo := makeRepo(t)
	embeddedGit := filepath.Join(repo, "vendor", "malicious", ".git")
	if err := os.MkdirAll(embeddedGit, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	writeFile(t, filepath.Join(embeddedGit, "config"), `[core]
	fsmonitor = /tmp/attack
`)
	findings := bareRepoScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", f.Severity)
	}
	if f.Module != "bare-repos" {
		t.Errorf("module = %q, want %q", f.Module, "bare-repos")
	}
	if !strings.Contains(f.Path, filepath.Join("vendor", "malicious", ".git")) {
		t.Errorf("path %q should reference the embedded .git path", f.Path)
	}
}

func TestBareRepos_EmbeddedGitDir_DeepNesting(t *testing.T) {
	repo := makeRepo(t)
	deepGit := filepath.Join(repo, "a", "b", "c", "d", "e", ".git")
	if err := os.MkdirAll(deepGit, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	findings := bareRepoScan(t, repo)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for deeply nested .git/, got %d", len(findings))
	}
}

func TestBareRepos_MultipleEmbeddedGitDirs(t *testing.T) {
	repo := makeRepo(t)
	for _, sub := range []string{"vendor/a", "vendor/b", "subprojects/c"} {
		dir := filepath.Join(repo, sub, ".git")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("setup %s: %v", dir, err)
		}
	}
	findings := bareRepoScan(t, repo)
	if len(findings) != 3 {
		t.Errorf("expected 3 findings, got %d: %v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Severity != scanner.Critical {
			t.Errorf("finding %q: severity = %v, want CRITICAL", f.Path, f.Severity)
		}
	}
}

func TestBareRepos_CaseVariant_GIT_IsCritical(t *testing.T) {
	// On Linux (case-sensitive FS), .GIT/ is a different entry from .git/ and
	// git will treat it as an embedded bare repo.
	if runtime.GOOS == "windows" {
		t.Skip("Windows is case-insensitive: .GIT/ resolves to .git/")
	}
	repo := makeRepo(t)
	upperGit := filepath.Join(repo, "src", ".GIT")
	if err := os.MkdirAll(upperGit, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	writeFile(t, filepath.Join(upperGit, "config"), "[core]\n\tfilemode = true\n")

	findings := bareRepoScan(t, repo)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for .GIT/ case variant, got %d: %v", len(findings), findings)
	}
	if findings[0].Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
}

func TestBareRepos_CaseVariant_GitMixedCase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows is case-insensitive")
	}
	repo := makeRepo(t)
	mixedGit := filepath.Join(repo, "subdir", ".Git")
	if err := os.MkdirAll(mixedGit, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	findings := bareRepoScan(t, repo)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for .Git/ mixed case, got %d: %v", len(findings), findings)
	}
}

func TestBareRepos_DotGitFile_NotFlagged(t *testing.T) {
	// A .git FILE (not directory) is how git worktrees reference their parent.
	// It is not an embedded bare repo.
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, "subdir", ".git"),
		"gitdir: ../../.git/worktrees/sub\n")
	findings := bareRepoScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for .git file (worktree ref), got %d", len(findings))
	}
}

func TestBareRepos_ModuleName(t *testing.T) {
	m := scanner.NewBareReposModule()
	if m.Name() != "bare-repos" {
		t.Errorf("Name() = %q, want %q", m.Name(), "bare-repos")
	}
}
