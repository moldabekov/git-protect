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
