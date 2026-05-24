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
