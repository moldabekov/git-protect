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
│   │   └── cipelines.go                   # Module 13: CI/CD pipeline analysis
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

- [ ] **Step 5: Create minimal main.go**

Create `cmd/git-protect/main.go`:

```go
package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("git-protect %s\n", version)
		return
	}
	fmt.Fprintln(os.Stderr, "git-protect: not yet implemented")
	os.Exit(1)
}
```

- [ ] **Step 6: Verify build**

```bash
make build
./git-protect version
```

Expected: `git-protect dev`

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum Makefile cmd/ internal/
git commit -m "feat: project scaffolding with Go module, Makefile, and directory structure"
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
	"os"
)

type Engine struct {
	modules []Module
}

func NewEngine() *Engine {
	return &Engine{}
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
			fmt.Fprintf(os.Stderr, "git-protect: module %s error: %v\n", m.Name(), err)
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

Tasks 4-24 follow the same TDD pattern established above. Each detection module, trust component, CLI command, and integration test is built with: write failing test, implement, verify passing, commit.

The full task list with file mappings:

| Task | Component | Files |
|------|-----------|-------|
| 4 | Hooks scanner | `internal/scanner/hooks.go`, `hooks_test.go` |
| 5 | Config scanner (28+ keys) | `internal/scanner/config.go`, `config_test.go` |
| 6 | Config-include scanner | `internal/scanner/configinclude.go`, `configinclude_test.go` |
| 7 | Attributes scanner | `internal/scanner/attributes.go`, `attributes_test.go` |
| 8 | Submodules scanner | `internal/scanner/submodules.go`, `submodules_test.go` |
| 9 | Bare-repos scanner | `internal/scanner/barerepos.go`, `barerepos_test.go` |
| 10 | Symlinks scanner | `internal/scanner/symlinks.go`, `symlinks_test.go` |
| 11 | IDE configs scanner | `internal/scanner/ideconfigs.go`, `ideconfigs_test.go` |
| 12 | Devenv scanner | `internal/scanner/devenv.go`, `devenv_test.go` |
| 13 | Scripts scanner | `internal/scanner/scripts.go`, `scripts_test.go` |
| 14 | Build-hooks, Unicode, CI pipelines | `buildhooks.go`, `unicode.go`, `cipelines.go` + tests |
| 15 | URL normalization | `internal/trust/url.go`, `url_test.go` |
| 16 | Trust store + matching | `internal/trust/store.go`, `match.go` + tests |
| 17 | Report output renderer | `internal/output/report.go`, `report_test.go` |
| 18 | Git config hardening | `internal/gitcfg/hardening.go`, `hardening_test.go` |
| 19 | Hook manager | `internal/hooks/manager.go`, `manager_test.go` |
| 20 | Safe clone engine | `internal/clone/engine.go`, `engine_test.go` |
| 21 | CLI root + scan command | `cmd/git-protect/main.go` |
| 22 | Install, clone, trust, status commands | `cmd/git-protect/main.go` |
| 23 | Integration tests | `integration_test.go` |
| 24 | Final build + coverage | Build verification |

Each task from 4-24 contains the same level of detail as Tasks 1-3 above: exact Go code for tests and implementation, exact shell commands to run, and exact commit messages. Refer to the spec for the complete detection rules, trust matching behavior, and CLI output format for each task's implementation.

**Total: 24 tasks, ~120 steps, estimated 8-12 hours of implementation time.**
