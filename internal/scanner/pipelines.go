package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// pipelinesModule scans CI/CD pipeline definitions for suspicious commands.
// Covers GitHub Actions workflows (.github/workflows/*.yml) and GitLab CI
// (.gitlab-ci.yml). Severity: MEDIUM.
type pipelinesModule struct{}

// NewPipelinesModule returns a Module that detects suspicious commands in CI
// pipeline definitions.
func NewPipelinesModule() Module {
	return &pipelinesModule{}
}

func (m *pipelinesModule) Name() string { return "ci-pipelines" }

// pipelinePattern is a heuristic pattern applied line-by-line to pipeline YAML.
type pipelinePattern struct {
	label   string
	pattern *regexp.Regexp
	detail  string
}

// ciSuspiciousPatterns are the heuristics applied to all CI pipeline files.
var ciSuspiciousPatterns = []pipelinePattern{
	{
		label:   "curl pipe shell",
		pattern: regexp.MustCompile(`curl\s[^|]*\|\s*(ba)?sh`),
		detail:  "Downloads and pipes to a shell in CI — can exfiltrate CI secrets (GITHUB_TOKEN, repository secrets) to an external server.",
	},
	{
		label:   "wget pipe shell",
		pattern: regexp.MustCompile(`wget\s[^|]*\|\s*(ba)?sh`),
		detail:  "Downloads and pipes to a shell in CI — can exfiltrate CI secrets to an external server.",
	},
	{
		label:   "base64 decode pipe shell",
		pattern: regexp.MustCompile(`base64\s+-d.*\|\s*(ba)?sh`),
		detail:  "Decodes a base64-encoded payload and executes it in CI — obfuscated command execution.",
	},
	{
		label:   "/dev/tcp in CI",
		pattern: regexp.MustCompile(`/dev/tcp/`),
		detail:  "TCP redirection in a CI step can establish a reverse shell or exfiltrate secrets out of band.",
	},
	{
		label:   "nc reverse shell in CI",
		pattern: regexp.MustCompile(`nc\s+-e\s+`),
		detail:  "netcat -e in CI can open a reverse shell back to an attacker-controlled host.",
	},
}

func (m *pipelinesModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	var findings []Finding

	// Scan .github/workflows/*.yml and *.yaml.
	workflowsDir := filepath.Join(sc.RepoPath, ".github", "workflows")
	if entries, err := os.ReadDir(workflowsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
				continue
			}
			info, infoErr := entry.Info()
			if infoErr != nil || info.Size() > maxScriptSize {
				continue
			}
			relPath := filepath.Join(".github", "workflows", name)
			wfPath := filepath.Join(workflowsDir, name)
			if f, scanErr := scanPipelineFile(wfPath, relPath, m.Name()); scanErr == nil {
				findings = append(findings, f...)
			}
		}
	}

	// Scan .gitlab-ci.yml (and .yaml variant) at the repo root.
	for _, name := range []string{".gitlab-ci.yml", ".gitlab-ci.yaml"} {
		ciPath := filepath.Join(sc.RepoPath, name)
		if info, err := os.Stat(ciPath); err == nil && info.Size() <= maxScriptSize {
			if f, err := scanPipelineFile(ciPath, name, m.Name()); err == nil {
				findings = append(findings, f...)
			}
		}
	}

	return findings, nil
}

// scanPipelineFile applies ciSuspiciousPatterns to a pipeline YAML file,
// line by line. Reports at most one finding per pattern label per file.
func scanPipelineFile(path, relPath, moduleName string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ci-pipelines: open %s: %w", path, err)
	}
	defer f.Close()

	reported := make(map[string]bool)
	var findings []Finding

	sc := bufio.NewScanner(f)
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := sc.Text()
		for _, pat := range ciSuspiciousPatterns {
			if reported[pat.label] {
				continue
			}
			if pat.pattern.MatchString(line) {
				reported[pat.label] = true
				findings = append(findings, Finding{
					Severity: Medium,
					Module:   moduleName,
					Path:     relPath,
					Message:  fmt.Sprintf("%s line %d: %s", relPath, lineNum, pat.label),
					Detail:   pat.detail,
				})
			}
		}
	}
	return findings, sc.Err()
}
