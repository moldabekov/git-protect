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

// scanLinesKeepCR is a bufio.SplitFunc that splits on \n but does NOT strip
// trailing \r, preserving carriage returns in the returned token. This is
// necessary to detect CVE-2025-48384 where a \r in a submodule path is used
// to smuggle a write to a different filesystem location.
func scanLinesKeepCR(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := strings.IndexByte(string(data), '\n'); i >= 0 {
		return i + 1, data[:i], nil // return everything up to (not including) \n
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil // request more data
}

// parseGitmodules parses the INI-format .gitmodules file and returns findings.
func parseGitmodules(r io.Reader, relPath string) ([]Finding, error) {
	sc := bufio.NewScanner(r)
	sc.Split(scanLinesKeepCR) // preserve \r so CR-smuggling is detectable
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
		raw := sc.Text()
		// Left-trim whitespace; right-trim spaces and tabs but keep \r.
		line := strings.TrimLeft(raw, " \t")
		line = strings.TrimRight(line, " \t")
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			flush()
			// Strip any trailing \r before lowercasing the section header.
			lower := strings.ToLower(strings.TrimRight(line, "\r"))
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
		// Preserve \r in value for CR-smuggling detection; only strip inline
		// comments and leading whitespace.
		val := strings.TrimLeft(line[eq+1:], " \t")
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

// truncate returns s truncated to at most maxLen runes, appending "..." if cut.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
