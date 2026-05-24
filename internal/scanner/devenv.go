package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// devenvModule detects dev environment files that auto-execute commands.
// .envrc with GIT_CONFIG_* variables: CRITICAL – bypasses all config-based protections.
// .envrc presence and devcontainer lifecycle hooks: HIGH.
type devenvModule struct{}

// NewDevenvModule returns a Module that detects dangerous dev environment files.
func NewDevenvModule() Module {
	return &devenvModule{}
}

func (m *devenvModule) Name() string { return "devenv" }

// devcontainerLifecycleHooks is the set of devcontainer.json keys that execute
// arbitrary commands during container creation or start.
var devcontainerLifecycleHooks = []string{
	"onCreateCommand",
	"updateContentCommand",
	"postCreateCommand",
	"postStartCommand",
	"postAttachCommand",
	"initializeCommand",
}

// gitConfigEnvPrefixes are environment variable names/prefixes whose presence in
// an .envrc can override git configuration, bypassing git-protect's defenses.
var gitConfigEnvPrefixes = []string{
	"GIT_CONFIG_COUNT",
	"GIT_CONFIG_KEY_",
	"GIT_CONFIG_VALUE_",
	"GIT_CONFIG_GLOBAL",
	"GIT_CONFIG_SYSTEM",
	"GIT_CONFIG_NOSYSTEM",
}

// Scan checks for dangerous dev environment files.
func (m *devenvModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	var findings []Finding

	devcontainerPath := filepath.Join(sc.RepoPath, ".devcontainer", "devcontainer.json")
	if f, err := scanDevcontainer(devcontainerPath); err == nil {
		findings = append(findings, f...)
	}

	envrcPath := filepath.Join(sc.RepoPath, ".envrc")
	if f, err := scanEnvrc(envrcPath); err == nil {
		findings = append(findings, f...)
	}

	return findings, nil
}

// scanDevcontainer checks devcontainer.json for lifecycle hook fields.
func scanDevcontainer(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err // File does not exist; not an error.
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("devenv: devcontainer.json parse error: %w", err)
	}

	var findings []Finding
	for _, hook := range devcontainerLifecycleHooks {
		raw, ok := cfg[hook]
		if !ok {
			continue
		}

		// The hook value can be a string or an array; capture its raw form for display.
		hookValue := strings.Trim(string(raw), `"`)
		findings = append(findings, Finding{
			Severity: High,
			Module:   "devenv",
			Path:     ".devcontainer/devcontainer.json",
			Message:  fmt.Sprintf("devcontainer lifecycle hook %q executes: %s", hook, truncate(hookValue, 80)),
			Detail: "devcontainer lifecycle hooks run automatically when a Codespace or dev container " +
				"is created/started. postCreateCommand is frequently abused to exfiltrate GITHUB_TOKEN.",
		})
	}

	return findings, nil
}

// scanEnvrc checks .envrc for its presence (HIGH) and for GIT_CONFIG_* variable
// exports (CRITICAL). direnv auto-executes .envrc on 'cd' into the directory.
func scanEnvrc(path string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err // File does not exist; not an error.
	}
	defer f.Close()

	// The mere presence of .envrc is HIGH: direnv auto-executes it on cd.
	findings := []Finding{
		{
			Severity: High,
			Module:   "devenv",
			Path:     ".envrc",
			Message:  ".envrc present – direnv will auto-execute this file when entering the directory",
			Detail: "direnv runs .envrc automatically when a shell enters the directory. " +
				"Any shell command in .envrc executes without further confirmation.",
		},
	}

	// Additionally scan for GIT_CONFIG_* environment variable exports.
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		varName := extractEnvVarName(line)
		if varName == "" {
			continue
		}

		upper := strings.ToUpper(varName)
		for _, prefix := range gitConfigEnvPrefixes {
			if strings.HasPrefix(upper, prefix) {
				findings = append(findings, Finding{
					Severity: Critical,
					Module:   "devenv",
					Path:     ".envrc",
					Message: fmt.Sprintf(
						".envrc line %d sets %s – overrides git configuration, bypassing all config-based protections",
						lineNum, varName),
					Detail: "GIT_CONFIG_COUNT/KEY/VALUE, GIT_CONFIG_GLOBAL, and GIT_CONFIG_SYSTEM environment " +
						"variables override git config at all scopes, including git-protect's hardened global " +
						"settings (core.hooksPath, core.fsmonitor, etc.).",
				})
				break
			}
		}
	}

	if err := sc.Err(); err != nil {
		return findings, fmt.Errorf("devenv: .envrc read error: %w", err)
	}

	return findings, nil
}

// extractEnvVarName returns the variable name from a shell assignment or export
// statement, e.g. "export FOO=bar" returns "FOO", "FOO=bar" returns "FOO".
// Returns "" if the line is not a recognisable variable assignment.
func extractEnvVarName(line string) string {
	// Strip optional "export" keyword.
	line = strings.TrimPrefix(line, "export ")
	line = strings.TrimSpace(line)

	eqIdx := strings.IndexByte(line, '=')
	if eqIdx <= 0 {
		return ""
	}
	name := line[:eqIdx]
	// Validate: variable names are [A-Za-z_][A-Za-z0-9_]*.
	for _, ch := range name {
		if !isIDChar(ch) {
			return ""
		}
	}
	return name
}

func isIDChar(ch rune) bool {
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
		(ch >= '0' && ch <= '9') || ch == '_'
}
