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
	scanner := bufio.NewScanner(f)
	var currentSection string // lowercased full section header including brackets

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
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
	if err := scanner.Err(); err != nil {
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
