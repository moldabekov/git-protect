package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ideConfigsModule detects IDE configuration files that auto-execute commands.
// Severity: HIGH – actively weaponized in the Contagious Interview campaign (2025-2026).
type ideConfigsModule struct{}

// NewIDEConfigsModule returns a Module that detects dangerous IDE configurations.
func NewIDEConfigsModule() Module {
	return &ideConfigsModule{}
}

func (m *ideConfigsModule) Name() string { return "ide-configs" }

// dangerousVSCodeSettings is the set of VS Code settings keys that, when set by
// a repo's .vscode/settings.json, redirect extension tooling to attacker-controlled
// binaries. Keys are lowercased for case-insensitive comparison.
var dangerousVSCodeSettings = []string{
	"git.path",
	"python.pythonpath",
	"python.defaultinterpreterpath",
	"terminal.integrated.shell.linux",
	"terminal.integrated.shell.osx",
	"terminal.integrated.shell.windows",
	"terminal.integrated.defaultprofile.linux",
	"terminal.integrated.defaultprofile.osx",
	"terminal.integrated.defaultprofile.windows",
	"eslint.nodepath",
	"prettier.prettierpath",
	"go.alternatetools",
	"go.gopath",
	"go.goroot",
	"rust-analyzer.server.path",
	"java.home",
	"maven.executable.path",
}

// Scan checks for dangerous IDE configuration files in the repository.
func (m *ideConfigsModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	var findings []Finding

	vscodeTasks := filepath.Join(sc.RepoPath, ".vscode", "tasks.json")
	if f, err := scanVSCodeTasks(vscodeTasks); err == nil {
		findings = append(findings, f...)
	}

	vscodeSettings := filepath.Join(sc.RepoPath, ".vscode", "settings.json")
	if f, err := scanVSCodeSettings(vscodeSettings); err == nil {
		findings = append(findings, f...)
	}

	ideaDir := filepath.Join(sc.RepoPath, ".idea")
	if f, err := scanIntelliJDir(ideaDir); err == nil {
		findings = append(findings, f...)
	}

	return findings, nil
}

// scanVSCodeTasks checks .vscode/tasks.json for tasks with runOn:folderOpen.
func scanVSCodeTasks(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err // File does not exist or is unreadable; not an error condition.
	}

	// Parse as a generic map so we handle arbitrary task shapes without a rigid schema.
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("ide-configs: tasks.json parse error: %w", err)
	}

	tasksRaw, ok := root["tasks"]
	if !ok {
		return nil, nil
	}

	var tasks []json.RawMessage
	if err := json.Unmarshal(tasksRaw, &tasks); err != nil {
		return nil, nil
	}

	var findings []Finding
	for i, taskRaw := range tasks {
		var task map[string]json.RawMessage
		if err := json.Unmarshal(taskRaw, &task); err != nil {
			continue
		}

		runOptionsRaw, hasRunOptions := task["runOptions"]
		if !hasRunOptions {
			continue
		}

		var runOptions map[string]json.RawMessage
		if err := json.Unmarshal(runOptionsRaw, &runOptions); err != nil {
			continue
		}

		runOnRaw, hasRunOn := runOptions["runOn"]
		if !hasRunOn {
			continue
		}

		var runOn string
		if err := json.Unmarshal(runOnRaw, &runOn); err != nil {
			continue
		}

		if strings.EqualFold(runOn, "folderOpen") {
			label := fmt.Sprintf("task[%d]", i)
			if labelRaw, ok := task["label"]; ok {
				_ = json.Unmarshal(labelRaw, &label)
			}
			findings = append(findings, Finding{
				Severity: High,
				Module:   "ide-configs",
				Path:     ".vscode/tasks.json",
				Message:  fmt.Sprintf("VS Code task %q has runOn:folderOpen – auto-executes on folder open", label),
				Detail:   "Tasks with runOn:folderOpen execute automatically when a developer opens the project in VS Code.",
			})
		}
	}

	return findings, nil
}

// scanVSCodeSettings checks .vscode/settings.json for dangerous key overrides.
func scanVSCodeSettings(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var settings map[string]json.RawMessage
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("ide-configs: settings.json parse error: %w", err)
	}

	var findings []Finding
	for key := range settings {
		for _, dangerous := range dangerousVSCodeSettings {
			if strings.EqualFold(key, dangerous) {
				findings = append(findings, Finding{
					Severity: High,
					Module:   "ide-configs",
					Path:     ".vscode/settings.json",
					Message:  fmt.Sprintf("VS Code setting %q overrides tool path – can redirect to attacker-controlled binary", key),
					Detail:   "Repo-local VS Code settings can redirect the interpreter, shell, or tool used by extensions to an arbitrary binary.",
				})
				break
			}
		}
	}

	return findings, nil
}

// scanIntelliJDir walks .idea/ and checks XML files for RunManager components.
func scanIntelliJDir(ideaDir string) ([]Finding, error) {
	entries, err := os.ReadDir(ideaDir)
	if err != nil {
		return nil, err // Directory does not exist; not an error.
	}

	var findings []Finding
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".xml") {
			continue
		}
		xmlPath := filepath.Join(ideaDir, entry.Name())
		data, err := os.ReadFile(xmlPath)
		if err != nil {
			continue
		}

		if bytes.Contains(data, []byte(`name="RunManager"`)) {
			relPath := filepath.Join(".idea", entry.Name())
			findings = append(findings, Finding{
				Severity: High,
				Module:   "ide-configs",
				Path:     relPath,
				Message:  fmt.Sprintf("JetBrains .idea/%s contains RunManager component – defines auto-run configurations", entry.Name()),
				Detail:   "JetBrains IDEs load run configurations from .idea/ workspace XML files automatically. Used in Contagious Interview campaign to execute malicious code on project open.",
			})
		}
	}

	return findings, nil
}
