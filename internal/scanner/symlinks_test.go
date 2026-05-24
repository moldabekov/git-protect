package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestSymlinksModule_NoSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewSymlinksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestSymlinksModule_InternalSymlink(t *testing.T) {
	// A symlink that points to a file inside the repo is safe.
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewSymlinksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("internal symlink should not be flagged, got %d findings", len(findings))
	}
}

func TestSymlinksModule_EscapingSymlink(t *testing.T) {
	// A symlink pointing to the temp dir's parent escapes the repo tree.
	dir := t.TempDir()
	link := filepath.Join(dir, "escape")
	outsideTarget := filepath.Dir(dir)
	if err := os.Symlink(outsideTarget, link); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewSymlinksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Error("escaping symlink should produce a finding")
	}
	if findings[0].Severity != scanner.High {
		t.Errorf("escaping symlink severity = %v, want HIGH", findings[0].Severity)
	}
}

func TestSymlinksModule_BrokenSymlink(t *testing.T) {
	// A broken symlink with an outside target should not panic or error.
	dir := t.TempDir()
	link := filepath.Join(dir, "broken")
	if err := os.Symlink("/nonexistent/path/outside", link); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewSymlinksModule()
	// Should not return an error even for unresolvable symlinks.
	_, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("broken symlink must not cause Scan to error: %v", err)
	}
}

func TestSymlinksModule_GitDirSkipped(t *testing.T) {
	// Symlinks inside .git/ must be ignored.
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Symlink inside .git pointing outside the repo.
	link := filepath.Join(gitDir, "evil")
	if err := os.Symlink(filepath.Dir(dir), link); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewSymlinksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("symlinks inside .git/ should be skipped, got %d findings", len(findings))
	}
}

func TestSymlinksModule_Name(t *testing.T) {
	m := scanner.NewSymlinksModule()
	if m.Name() != "symlinks" {
		t.Errorf("Name() = %q, want %q", m.Name(), "symlinks")
	}
}
