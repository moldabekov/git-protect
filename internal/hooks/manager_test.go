package hooks_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/moldabekov/git-protect/internal/hooks"
)

func TestInstall_CreatesAllThreeHooks(t *testing.T) {
	dir := t.TempDir()
	binaryPath := "/usr/local/bin/git-protect"

	if err := hooks.Install(dir, binaryPath); err != nil {
		t.Fatalf("Install: %v", err)
	}

	expected := []string{"post-checkout", "post-merge", "post-rewrite"}
	for _, name := range expected {
		hookPath := filepath.Join(dir, name)
		if _, err := os.Stat(hookPath); os.IsNotExist(err) {
			t.Errorf("hook %q was not created", hookPath)
		}
	}
}

func TestInstall_HooksAreExecutable(t *testing.T) {
	dir := t.TempDir()
	binaryPath := "/usr/local/bin/git-protect"

	if err := hooks.Install(dir, binaryPath); err != nil {
		t.Fatalf("Install: %v", err)
	}

	for _, name := range []string{"post-checkout", "post-merge", "post-rewrite"} {
		hookPath := filepath.Join(dir, name)
		info, err := os.Stat(hookPath)
		if err != nil {
			t.Fatalf("Stat %q: %v", hookPath, err)
		}
		if info.Mode().Perm()&0111 == 0 {
			t.Errorf("hook %q is not executable (mode %04o)", hookPath, info.Mode().Perm())
		}
	}
}

func TestInstall_HooksContainBinaryPath(t *testing.T) {
	dir := t.TempDir()
	binaryPath := "/home/user/.local/bin/git-protect"

	if err := hooks.Install(dir, binaryPath); err != nil {
		t.Fatalf("Install: %v", err)
	}

	hookPath := filepath.Join(dir, "post-checkout")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(content) == "" {
		t.Error("hook file is empty")
	}
	if !containsString(string(content), binaryPath) {
		t.Errorf("hook script does not contain binary path %q\nscript:\n%s", binaryPath, content)
	}
}

func TestInstall_HooksContainScanHookMode(t *testing.T) {
	dir := t.TempDir()
	if err := hooks.Install(dir, "/usr/bin/git-protect"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	hookPath := filepath.Join(dir, "post-checkout")
	content, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !containsString(string(content), "--hook-mode") {
		t.Errorf("hook script does not contain --hook-mode:\n%s", content)
	}
	if !containsString(string(content), "scan") {
		t.Errorf("hook script does not contain 'scan':\n%s", content)
	}
}

func TestInstall_Idempotent(t *testing.T) {
	dir := t.TempDir()
	binaryPath := "/usr/local/bin/git-protect"

	if err := hooks.Install(dir, binaryPath); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	if err := hooks.Install(dir, binaryPath); err != nil {
		t.Fatalf("second Install: %v", err)
	}
}

func TestUninstall_RemovesAllHooks(t *testing.T) {
	dir := t.TempDir()
	if err := hooks.Install(dir, "/usr/bin/git-protect"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	if err := hooks.Uninstall(dir); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	for _, name := range []string{"post-checkout", "post-merge", "post-rewrite"} {
		hookPath := filepath.Join(dir, name)
		if _, err := os.Stat(hookPath); !os.IsNotExist(err) {
			t.Errorf("hook %q still exists after Uninstall", hookPath)
		}
	}
}

func TestUninstall_IdempotentWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := hooks.Uninstall(dir); err != nil {
		t.Fatalf("Uninstall on empty dir: %v", err)
	}
}

func containsString(haystack, needle string) bool {
	return len(haystack) > 0 && len(needle) > 0 &&
		len(haystack) >= len(needle) &&
		findString(haystack, needle)
}

func findString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
