# git-protect Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go CLI that protects developers from malicious git repositories by scanning for 13 attack vector categories before code can execute.

**Architecture:** Single Go binary with modular scanner engine. Each detection module implements a `Module` interface and is registered with the engine. The CLI uses cobra for commands. Trust store is TOML-based with XDG paths. Safe-clone wrapper uses `git clone --no-checkout` then scan then checkout.

**Tech Stack:** Go 1.22+, cobra (CLI), BurntSushi/toml (config), fatih/color (output), standard library for git operations (os/exec).

**Spec:** `docs/superpowers/specs/2026-05-24-git-protect-design.md`

---

## File Structure

```
git-protect/
├── cmd/git-protect/main.go                 # Entry point
├── internal/
│   ├── scanner/
│   │   ├── types.go                        # Severity, Finding, Report, Module interface
│   │   ├── engine.go                       # Orchestrator — runs modules, aggregates results
│   │   ├── hooks.go                        # Module 1: .git/hooks/ executable scan
│   │   ├── config.go                       # Module 2: .git/config dangerous directives
│   │   ├── configinclude.go               # Module 3: include/includeIf resolution
│   │   ├── attributes.go                  # Module 4: .gitattributes filter/diff/merge
│   │   ├── submodules.go                  # Module 5: .gitmodules ext::/traversal/CR
│   │   ├── symlinks.go                    # Module 6: symlinks escaping repo tree
│   │   ├── barerepos.go                   # Module 7: embedded .git/ directories
│   │   ├── ideconfigs.go                  # Module 8: .vscode/tasks.json, .idea/
│   │   ├── devenv.go                      # Module 9: .devcontainer/, .envrc
│   │   ├── scripts.go                     # Module 10: exfiltration pattern heuristics
│   │   ├── buildhooks.go                  # Module 11: package.json postinstall, Makefile
│   │   ├── unicode.go                     # Module 12: BiDi/homoglyph detection
│   │   └── pipelines.go                   # Module 13: CI/CD pipeline analysis
│   ├── trust/
│   │   ├── store.go                       # CRUD for trust.toml with security checks
│   │   ├── url.go                         # URL normalization (SSH, HTTPS, IDN, percent-encoding)
│   │   └── match.go                       # Pattern matching against normalized URLs
│   ├── clone/
│   │   └── engine.go                      # Safe clone: no-checkout -> scan -> checkout
│   ├── hooks/
│   │   └── manager.go                     # Install/uninstall/chain git hooks
│   ├── gitcfg/
│   │   └── hardening.go                   # Git config hardening (read/write global config)
│   └── output/
│       └── report.go                      # Render findings to terminal and JSON
├── go.mod
├── go.sum
└── Makefile
```

---

## Phase 1: Foundation

### Task 1: Project Scaffolding

**Files:**
- Create: `go.mod`
- Create: `Makefile`
- Create: `cmd/git-protect/main.go`

- [ ] **Step 1: Initialize Go module**

```bash
cd /home/moldabekov/Work/Projects/git/git-protect
go mod init github.com/moldabekov/git-protect
```

- [ ] **Step 2: Install dependencies**

```bash
go get github.com/spf13/cobra@latest
go get github.com/BurntSushi/toml@latest
go get github.com/fatih/color@latest
```

- [ ] **Step 3: Create directory structure**

```bash
mkdir -p cmd/git-protect internal/{scanner,trust,clone,hooks,gitcfg,output}
```

- [ ] **Step 4: Create Makefile**

Create `Makefile`:

```makefile
BINARY := git-protect
VERSION := 0.1.0
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test lint clean install

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/git-protect

test:
	go test -race -count=1 ./...

test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	go vet ./...

clean:
	rm -f $(BINARY) coverage.out

install: build
	cp $(BINARY) $(GOPATH)/bin/
```

- [ ] **Step 5: Create .gitignore**

Create `.gitignore`:

```
git-protect
coverage.out
*.test
```

- [ ] **Step 6: Create minimal main.go with cobra**

Create `cmd/git-protect/main.go`:

```go
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:   "git-protect",
		Short: "Protect against malicious git repositories",
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("git-protect %s\n", version)
		},
	})

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
```

- [ ] **Step 7: Create XDG path resolver**

Create `internal/paths/paths.go`:

```go
package paths

import (
	"os"
	"path/filepath"
)

func ConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "git-protect")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "git-protect")
}

func HooksDir() string {
	return filepath.Join(ConfigDir(), "hooks")
}

func TrustStorePath() string {
	return filepath.Join(ConfigDir(), "trust.toml")
}
```

- [ ] **Step 8: Verify build**

```bash
make build
./git-protect version
```

Expected: `git-protect dev`

- [ ] **Step 9: Commit**

```bash
git add go.mod go.sum Makefile .gitignore cmd/ internal/
git commit -m "feat: project scaffolding with Go module, cobra CLI, XDG paths, and directory structure"
```

---

### Task 2: Core Types and Scanner Interface

**Files:**
- Create: `internal/scanner/types.go`
- Test: `internal/scanner/types_test.go`

- [ ] **Step 1: Write tests for core types**

Create `internal/scanner/types_test.go`:

```go
package scanner_test

import (
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  scanner.Severity
		want string
	}{
		{scanner.Critical, "CRITICAL"},
		{scanner.High, "HIGH"},
		{scanner.Medium, "MEDIUM"},
		{scanner.Info, "INFO"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestSeverityBlocks(t *testing.T) {
	if !scanner.Critical.Blocks() {
		t.Error("CRITICAL should block")
	}
	if !scanner.High.Blocks() {
		t.Error("HIGH should block")
	}
	if scanner.Medium.Blocks() {
		t.Error("MEDIUM should not block")
	}
	if scanner.Info.Blocks() {
		t.Error("INFO should not block")
	}
}

func TestReportHasBlocking(t *testing.T) {
	r := scanner.Report{
		Findings: []scanner.Finding{
			{Severity: scanner.Medium, Module: "scripts", Message: "curl found"},
		},
	}
	if r.HasBlocking() {
		t.Error("report with only MEDIUM should not have blocking findings")
	}

	r.Findings = append(r.Findings, scanner.Finding{
		Severity: scanner.Critical, Module: "config", Message: "fsmonitor",
	})
	if !r.HasBlocking() {
		t.Error("report with CRITICAL should have blocking findings")
	}
}

func TestReportFilterBySeverity(t *testing.T) {
	r := scanner.Report{
		Findings: []scanner.Finding{
			{Severity: scanner.Critical, Module: "config", Message: "fsmonitor"},
			{Severity: scanner.Medium, Module: "scripts", Message: "curl"},
			{Severity: scanner.Info, Module: "ci", Message: "workflow"},
		},
	}
	filtered := r.AtOrAbove(scanner.Medium)
	if len(filtered) != 2 {
		t.Errorf("AtOrAbove(Medium) returned %d findings, want 2", len(filtered))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/scanner/ -v
```

Expected: compilation errors (types not defined)

- [ ] **Step 3: Implement core types**

Create `internal/scanner/types.go`:

```go
package scanner

import "context"

// Severity levels ordered low-to-high. This ordering is load-bearing:
// Blocks() and AtOrAbove() use >= comparison. Do not reorder.
type Severity int

const (
	Info Severity = iota
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Info:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) Blocks() bool {
	return s >= High
}

type Finding struct {
	Severity Severity
	Module   string
	Path     string
	Message  string
	Detail   string
}

type Report struct {
	Findings []Finding
}

func (r Report) HasBlocking() bool {
	for _, f := range r.Findings {
		if f.Severity.Blocks() {
			return true
		}
	}
	return false
}

func (r Report) AtOrAbove(min Severity) []Finding {
	var result []Finding
	for _, f := range r.Findings {
		if f.Severity >= min {
			result = append(result, f)
		}
	}
	return result
}

type ScanContext struct {
	RepoPath    string
	PreCheckout bool
	GitBin      string
}

type Module interface {
	Name() string
	Scan(ctx context.Context, sc ScanContext) ([]Finding, error)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/scanner/ -v
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/
git commit -m "feat: core scanner types -- Severity, Finding, Report, Module interface"
```

---

### Task 3: Scanner Engine (Orchestrator)

**Files:**
- Create: `internal/scanner/engine.go`
- Test: `internal/scanner/engine_test.go`

- [ ] **Step 1: Write tests for the engine**

Create `internal/scanner/engine_test.go`:

```go
package scanner_test

import (
	"context"
	"errors"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

type fakeModule struct {
	name     string
	findings []scanner.Finding
	err      error
}

func (f *fakeModule) Name() string { return f.name }
func (f *fakeModule) Scan(_ context.Context, _ scanner.ScanContext) ([]scanner.Finding, error) {
	return f.findings, f.err
}

func TestEngineRunsAllModules(t *testing.T) {
	e := scanner.NewEngine()
	e.Register(&fakeModule{
		name: "mod1",
		findings: []scanner.Finding{
			{Severity: scanner.Critical, Module: "mod1", Message: "bad config"},
		},
	})
	e.Register(&fakeModule{
		name: "mod2",
		findings: []scanner.Finding{
			{Severity: scanner.Medium, Module: "mod2", Message: "suspicious script"},
		},
	})

	report, err := e.Scan(context.Background(), scanner.ScanContext{RepoPath: "/tmp/fake"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 2 {
		t.Errorf("got %d findings, want 2", len(report.Findings))
	}
	if !report.HasBlocking() {
		t.Error("report should have blocking findings")
	}
}

func TestEngineSkipsModulesOnFilter(t *testing.T) {
	e := scanner.NewEngine()
	e.Register(&fakeModule{name: "config", findings: []scanner.Finding{
		{Severity: scanner.Critical, Module: "config", Message: "fsmonitor"},
	}})
	e.Register(&fakeModule{name: "scripts", findings: []scanner.Finding{
		{Severity: scanner.Medium, Module: "scripts", Message: "curl"},
	}})

	report, err := e.ScanModules(context.Background(), scanner.ScanContext{RepoPath: "/tmp/fake"}, []string{"config"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Errorf("got %d findings, want 1", len(report.Findings))
	}
	if report.Findings[0].Module != "config" {
		t.Errorf("got module %q, want %q", report.Findings[0].Module, "config")
	}
}

func TestEngineContinuesOnModuleError(t *testing.T) {
	e := scanner.NewEngine()
	e.Register(&fakeModule{name: "broken", err: errors.New("module failed")})
	e.Register(&fakeModule{name: "working", findings: []scanner.Finding{
		{Severity: scanner.Medium, Module: "working", Message: "ok"},
	}})

	report, err := e.Scan(context.Background(), scanner.ScanContext{RepoPath: "/tmp/fake"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Errorf("got %d findings, want 1 (broken module should be skipped)", len(report.Findings))
	}
}

func TestEngineModuleNames(t *testing.T) {
	e := scanner.NewEngine()
	e.Register(&fakeModule{name: "config"})
	e.Register(&fakeModule{name: "hooks"})
	names := e.ModuleNames()
	if len(names) != 2 {
		t.Fatalf("got %d names, want 2", len(names))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/scanner/ -v -run Engine
```

Expected: compilation errors (NewEngine not defined)

- [ ] **Step 3: Implement the engine**

Create `internal/scanner/engine.go`:

```go
package scanner

import (
	"context"
	"fmt"
	"io"
	"os"
)

type ModuleError struct {
	Module string
	Err    error
}

type Engine struct {
	modules []Module
	ErrLog  io.Writer
}

func NewEngine() *Engine {
	return &Engine{ErrLog: os.Stderr}
}

func (e *Engine) Register(m Module) {
	e.modules = append(e.modules, m)
}

func (e *Engine) ModuleNames() []string {
	names := make([]string, len(e.modules))
	for i, m := range e.modules {
		names[i] = m.Name()
	}
	return names
}

func (e *Engine) Scan(ctx context.Context, sc ScanContext) (Report, error) {
	return e.scanModules(ctx, sc, nil)
}

func (e *Engine) ScanModules(ctx context.Context, sc ScanContext, only []string) (Report, error) {
	return e.scanModules(ctx, sc, only)
}

func (e *Engine) scanModules(ctx context.Context, sc ScanContext, only []string) (Report, error) {
	allowed := make(map[string]bool)
	for _, name := range only {
		allowed[name] = true
	}

	var report Report
	for _, m := range e.modules {
		if len(only) > 0 && !allowed[m.Name()] {
			continue
		}
		findings, err := m.Scan(ctx, sc)
		if err != nil {
			fmt.Fprintf(e.ErrLog, "git-protect: module %s error: %v\n", m.Name(), err)
			continue
		}
		report.Findings = append(report.Findings, findings...)
	}
	return report, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/scanner/ -v
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/engine.go internal/scanner/engine_test.go
git commit -m "feat: scanner engine orchestrator with module filtering and error resilience"
```

---

## Phase 2-7: Remaining Tasks

Full implementation code for Tasks 4-24 is in the supplementary file:

**`docs/superpowers/plans/2026-05-24-git-protect-tasks-4-24.md`**

Each task contains complete TDD steps: test file with concrete fixtures, implementation file with full Go code, bash commands with expected outputs, and commit messages. The supplementary file covers:

- **Tasks 4-9**: Critical detection modules (hooks, config with 28+ keys, config-include, attributes, submodules, bare-repos)
- **Tasks 10-14**: Remaining modules (symlinks, IDE configs, devenv, scripts, build-hooks, unicode, CI pipelines — each as a separate subtask)
- **Task 15**: URL normalization with SSH/HTTPS/IDN/percent-encoding handling
- **Task 16**: Trust store with 0600 permissions, symlink rejection, ownership check, atomic writes, pattern matching
- **Task 17**: Report renderer (terminal + JSON output)
- **Task 18**: Git config hardening with backup/restore and XDG path resolution
- **Task 19**: Hook manager with hook chaining for trusted repos
- **Task 20**: Safe clone engine with TOCTOU re-verification, `--recurse-submodules` interception, `--bare`/`--mirror` handling, `--force`/`--trust` overrides, partial clone degradation warning
- **Task 21**: CLI root with cobra, scan command (with `--json`, `--severity`, `--modules`, `--exit-code`, `--hook-mode` flags)
- **Task 22**: install (with `--alias`, `--dry-run`, Husky/pre-commit conflict detection), uninstall, clone (with `--force`, `--trust` + TTY check, `--bare`/`--mirror`), trust (with TTY confirmation for `add -y`), status (with `safe.directory` warning), version (with `--check` + GitHub API)
- **Task 23**: Integration tests (malicious config, submodule attacks, CVE regression, TOCTOU, hook chaining)
- **Task 24**: Final build, coverage verification, .gitignore

**Total: 24 tasks, ~120 steps, estimated 8-12 hours of implementation time.**
