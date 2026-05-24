package trust_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moldabekov/git-protect/internal/trust"
)

func newTempStore(t *testing.T) (*trust.Store, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.toml")
	return trust.NewStore(path), path
}

func TestStoreAddListRemove(t *testing.T) {
	s, _ := newTempStore(t)

	// Empty initially.
	entries, err := s.Load()
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}

	// Add an entry.
	err = s.Add(trust.Entry{
		Pattern: "github.com/myorg/*",
		Type:    "org",
		Added:   time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC),
		Note:    "test org",
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	entries, err = s.Load()
	if err != nil {
		t.Fatalf("Load after Add: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Pattern != "github.com/myorg/*" {
		t.Errorf("pattern = %q, want %q", entries[0].Pattern, "github.com/myorg/*")
	}

	// Add duplicate — should be idempotent.
	err = s.Add(trust.Entry{Pattern: "github.com/myorg/*", Type: "org"})
	if err != nil {
		t.Fatalf("Add duplicate: %v", err)
	}
	entries, _ = s.Load()
	if len(entries) != 1 {
		t.Errorf("duplicate add created extra entry, got %d entries", len(entries))
	}

	// Remove.
	err = s.Remove("github.com/myorg/*")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	entries, _ = s.Load()
	if len(entries) != 0 {
		t.Errorf("after Remove expected 0 entries, got %d", len(entries))
	}
}

func TestStoreFilePermissions(t *testing.T) {
	s, path := newTempStore(t)

	err := s.Add(trust.Entry{Pattern: "github.com/test/repo", Type: "repo"})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("trust store permissions = %04o, want 0600", perm)
	}
}

func TestStoreRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real.toml")
	linkFile := filepath.Join(dir, "trust.toml")

	if err := os.WriteFile(realFile, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realFile, linkFile); err != nil {
		t.Skip("symlinks not supported on this filesystem")
	}

	s := trust.NewStore(linkFile)
	_, err := s.Load()
	if err == nil {
		t.Fatal("expected error for symlink trust store, got nil")
	}
}

func TestStoreRejectsWrongPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trust.toml")

	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	s := trust.NewStore(path)
	_, err := s.Load()
	if err == nil {
		t.Fatal("expected error for wrong permissions, got nil")
	}
}

func TestStoreIsTrusted(t *testing.T) {
	s, _ := newTempStore(t)

	_ = s.Add(trust.Entry{Pattern: "github.com/myorg/*", Type: "org"})
	_ = s.Add(trust.Entry{Pattern: "github.com/torvalds/linux", Type: "repo"})
	_ = s.Add(trust.Entry{Pattern: "gitlab.internal.corp/*", Type: "host"})

	trusted := []string{
		"https://github.com/myorg/any-repo.git",
		"git@github.com:myorg/another.git",
		"https://github.com/torvalds/linux",
		"https://gitlab.internal.corp/team/project",
	}
	untrusted := []string{
		"https://github.com/evil/repo",
		"https://evil.com/myorg/repo",
		"/home/user/localrepo",
		"file:///tmp/repo",
	}

	for _, url := range trusted {
		ok, err := s.IsTrusted(url)
		if err != nil {
			t.Fatalf("IsTrusted(%q): %v", url, err)
		}
		if !ok {
			t.Errorf("IsTrusted(%q) = false, want true", url)
		}
	}
	for _, url := range untrusted {
		ok, err := s.IsTrusted(url)
		if err != nil {
			t.Fatalf("IsTrusted(%q): %v", url, err)
		}
		if ok {
			t.Errorf("IsTrusted(%q) = true, want false", url)
		}
	}
}

func TestStoreLocalPathsAlwaysUntrusted(t *testing.T) {
	s, _ := newTempStore(t)

	// Even with a wildcard that would theoretically match.
	_ = s.Add(trust.Entry{Pattern: "*", Type: "host"})

	localPaths := []string{
		"/home/user/repo",
		"./repo",
		"file:///tmp/myrepo",
	}
	for _, p := range localPaths {
		ok, err := s.IsTrusted(p)
		if err != nil {
			t.Fatalf("IsTrusted(%q): %v", p, err)
		}
		if ok {
			t.Errorf("local path %q should never be trusted", p)
		}
	}
}
