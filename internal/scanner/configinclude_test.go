package scanner_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func includeConfigScan(t *testing.T, repo string) []scanner.Finding {
	t.Helper()
	m := scanner.NewConfigIncludeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("configinclude scan error: %v", err)
	}
	return findings
}

func TestConfigInclude_NoIncludes(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	repositoryformatversion = 0
	filemode = true
[remote "origin"]
	url = https://github.com/legit/project.git
`)
	findings := includeConfigScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

func TestConfigInclude_IncludePath_IsCritical(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	repositoryformatversion = 0
[include]
	path = /tmp/attacker.cfg
`)
	findings := includeConfigScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", f.Severity)
	}
	if f.Module != "config-include" {
		t.Errorf("module = %q, want %q", f.Module, "config-include")
	}
	if !strings.Contains(f.Message, "include.path") {
		t.Errorf("message %q should contain 'include.path'", f.Message)
	}
	if !strings.Contains(f.Detail, "/tmp/attacker.cfg") {
		t.Errorf("detail %q should contain the included path value", f.Detail)
	}
	if !strings.Contains(f.Path, filepath.Join(".git", "config")) {
		t.Errorf("path %q should reference .git/config", f.Path)
	}
}

func TestConfigInclude_IncludeIfGitdir_IsCritical(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	repositoryformatversion = 0
[includeIf "gitdir:/home/victim/projects/"]
	path = /tmp/conditional-attack.cfg
`)
	findings := includeConfigScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", f.Severity)
	}
	if !strings.Contains(f.Message, "includeIf") {
		t.Errorf("message %q should contain 'includeIf'", f.Message)
	}
}

func TestConfigInclude_IncludeIfOnbranch_IsCritical(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[includeIf "onbranch:main"]
	path = ~/.config/git-attack/config
`)
	findings := includeConfigScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
}

func TestConfigInclude_MultipleIncludes_AllReported(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	repositoryformatversion = 0
[include]
	path = /tmp/first.cfg
[include]
	path = /tmp/second.cfg
[includeIf "gitdir:~/projects/"]
	path = /tmp/conditional.cfg
`)
	findings := includeConfigScan(t, repo)
	if len(findings) != 3 {
		t.Errorf("expected 3 findings, got %d: %v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Severity != scanner.Critical {
			t.Errorf("finding %q: severity = %v, want CRITICAL", f.Message, f.Severity)
		}
	}
}

func TestConfigInclude_MissingConfigFile_NoError(t *testing.T) {
	repo := makeRepo(t)
	m := scanner.NewConfigIncludeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("scanner must not error on missing config, got: %v", err)
	}
	_ = findings
}

func TestConfigInclude_RelativeIncludePath(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[include]
	path = ../../../tmp/outside-repo.cfg
`)
	findings := includeConfigScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for relative path include, got %d", len(findings))
	}
}

func TestConfigInclude_ModuleName(t *testing.T) {
	m := scanner.NewConfigIncludeModule()
	if m.Name() != "config-include" {
		t.Errorf("Name() = %q, want %q", m.Name(), "config-include")
	}
}
