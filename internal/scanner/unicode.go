package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// unicodeModule scans source files for BiDi (bidirectional) control characters.
// These are the "Trojan Source" characters (CVE-2021-42574) that make code
// appear different to human reviewers than how the compiler interprets it.
// Severity: MEDIUM.
type unicodeModule struct{}

// NewUnicodeModule returns a Module that detects BiDi control characters in
// source files.
func NewUnicodeModule() Module {
	return &unicodeModule{}
}

func (m *unicodeModule) Name() string { return "unicode" }

// unicodeSourceExtensions is the set of file extensions that will be scanned.
// Prose documents (README, Markdown) are excluded because BiDi characters may
// appear legitimately in Arabic/Hebrew text.
var unicodeSourceExtensions = map[string]bool{
	".go":    true,
	".py":    true,
	".js":    true,
	".ts":    true,
	".jsx":   true,
	".tsx":   true,
	".c":     true,
	".cpp":   true,
	".h":     true,
	".hpp":   true,
	".java":  true,
	".rs":    true,
	".rb":    true,
	".php":   true,
	".cs":    true,
	".swift": true,
	".kt":    true,
	".scala": true,
}

// unicodeSkipDirs mirrors scriptSkipDirs from scripts.go.
var unicodeSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
}

// bidiSeq is one UTF-8 encoded BiDi control character sequence with its label.
type bidiSeq struct {
	codepoint string
	raw       []byte
}

// bidiControlSequences lists the UTF-8 byte sequences for all BiDi control
// characters flagged by CVE-2021-42574 (Trojan Source).
//
// Codepoint → UTF-8:
//
//	U+200E  LTR MARK                    E2 80 8E
//	U+200F  RTL MARK                    E2 80 8F
//	U+202A  LTR EMBEDDING               E2 80 AA
//	U+202B  RTL EMBEDDING               E2 80 AB
//	U+202C  POP DIRECTIONAL FORMATTING  E2 80 AC
//	U+202D  LTR OVERRIDE                E2 80 AD
//	U+202E  RTL OVERRIDE                E2 80 AE
//	U+2066  LTR ISOLATE                 E2 81 A6
//	U+2067  RTL ISOLATE                 E2 81 A7
//	U+2068  FIRST STRONG ISOLATE        E2 81 A8
//	U+2069  POP DIRECTIONAL ISOLATE     E2 81 A9
var bidiControlSequences = []bidiSeq{
	{"U+200E (LTR MARK)", []byte{0xE2, 0x80, 0x8E}},
	{"U+200F (RTL MARK)", []byte{0xE2, 0x80, 0x8F}},
	{"U+202A (LTR EMBEDDING)", []byte{0xE2, 0x80, 0xAA}},
	{"U+202B (RTL EMBEDDING)", []byte{0xE2, 0x80, 0xAB}},
	{"U+202C (POP DIRECTIONAL FORMATTING)", []byte{0xE2, 0x80, 0xAC}},
	{"U+202D (LTR OVERRIDE)", []byte{0xE2, 0x80, 0xAD}},
	{"U+202E (RTL OVERRIDE)", []byte{0xE2, 0x80, 0xAE}},
	{"U+2066 (LTR ISOLATE)", []byte{0xE2, 0x81, 0xA6}},
	{"U+2067 (RTL ISOLATE)", []byte{0xE2, 0x81, 0xA7}},
	{"U+2068 (FIRST STRONG ISOLATE)", []byte{0xE2, 0x81, 0xA8}},
	{"U+2069 (POP DIRECTIONAL ISOLATE)", []byte{0xE2, 0x81, 0xA9}},
}

func (m *unicodeModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	var findings []Finding

	walkErr := filepath.WalkDir(sc.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if unicodeSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !unicodeSourceExtensions[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil || info.Size() > maxScriptSize {
			return nil // skip files > 1 MB
		}
		fileFindings, scanErr := scanUnicodeFile(path, sc.RepoPath, m.Name())
		if scanErr != nil {
			return nil
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	if walkErr != nil {
		return findings, fmt.Errorf("unicode: walk %s: %w", sc.RepoPath, walkErr)
	}
	return findings, nil
}

// scanUnicodeFile scans a single file for BiDi control character sequences.
// Reports at most one finding per unique codepoint per file.
func scanUnicodeFile(path, repoPath, moduleName string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unicode: open %s: %w", path, err)
	}
	defer f.Close()

	relPath, _ := filepath.Rel(repoPath, path)
	reported := make(map[string]bool)

	var findings []Finding
	sc := bufio.NewScanner(f)
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := sc.Bytes()
		for _, bidi := range bidiControlSequences {
			if reported[bidi.codepoint] {
				continue
			}
			if bytes.Contains(line, bidi.raw) {
				reported[bidi.codepoint] = true
				findings = append(findings, Finding{
					Severity: Medium,
					Module:   moduleName,
					Path:     relPath,
					Message: fmt.Sprintf(
						"%s line %d: BiDi control character %s (Trojan Source / CVE-2021-42574)",
						relPath, lineNum, bidi.codepoint),
					Detail: "BiDi control characters alter the visual rendering order of " +
						"text, making code appear different to reviewers than how the " +
						"compiler/interpreter processes it.",
				})
			}
		}
	}
	return findings, sc.Err()
}
