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
