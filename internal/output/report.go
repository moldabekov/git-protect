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
