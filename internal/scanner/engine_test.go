package scanner_test

import (
	"bytes"
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
	e.ErrLog = &bytes.Buffer{}
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
