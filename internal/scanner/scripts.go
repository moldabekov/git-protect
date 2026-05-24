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

// maxScriptSize is the maximum file size scanned by the scripts and unicode
// modules. Files larger than this are skipped to avoid reading minified or
// generated bundles.
const maxScriptSize = 1024 * 1024 // 1 MB

// scriptsModule performs heuristic scanning of shell, Python, and JavaScript
// files for exfiltration patterns and reverse-shell indicators.
// Severity: MEDIUM.
type scriptsModule struct{}

// NewScriptsModule returns a Module that detects exfiltration patterns in
// .sh/.py/.js files.
func NewScriptsModule() Module {
	return &scriptsModule{}
}

func (m *scriptsModule) Name() string { return "scripts" }

// scriptExtensions is the set of file extensions that will be scanned.
var scriptExtensions = map[string]bool{
	".sh":  true,
	".py":  true,
	".js":  true,
	".ts":  true,
	".rb":  true,
	".pl":  true,
	".php": true,
}

// scriptSkipDirs is the set of directory names whose subtrees are always skipped.
var scriptSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
}

// scriptPattern is a compiled regular expression with a human-readable label.
type scriptPattern struct {
	label   string
	pattern *regexp.Regexp
	detail  string
}

// exfiltrationPatterns are the heuristic patterns checked on every scanned line.
var exfiltrationPatterns = []scriptPattern{
	// Network exfiltration: download and execute.
	{
		label:   "curl pipe shell",
		pattern: regexp.MustCompile(`curl\s[^|]*\|\s*(ba)?sh`),
		detail:  "Downloads and pipes content directly to a shell interpreter, a classic initial-access technique.",
	},
	{
		label:   "wget pipe bash",
		pattern: regexp.MustCompile(`wget\s[^|]*\|\s*(ba)?sh`),
		detail:  "Downloads and pipes content directly to a shell interpreter.",
	},
	{
		label:   "/dev/tcp reverse shell",
		pattern: regexp.MustCompile(`/dev/tcp/`),
		detail:  "bash built-in TCP redirection used in reverse shell payloads.",
	},
	{
		label:   "nc -e reverse shell",
		pattern: regexp.MustCompile(`nc\s+-e\s+`),
		detail:  "netcat with -e flag enables a remote shell.",
	},
	{
		label:   "base64 decode pipe shell",
		pattern: regexp.MustCompile(`base64\s+-d.*\|\s*(ba)?sh`),
		detail:  "Decodes a base64-encoded payload and pipes it to a shell — classic obfuscation technique.",
	},
	{
		label:   "eval base64 decode (Python)",
		pattern: regexp.MustCompile(`exec\s*\(\s*(__import__\s*\(\s*['"]base64['"]|base64\.b64decode)`),
		detail:  "Executes base64-decoded payload via exec() — obfuscated code execution.",
	},
	// Credential access patterns.
	{
		label:   "SSH private key access",
		pattern: regexp.MustCompile(`~/\.ssh/id_(rsa|ed25519|ecdsa|dsa)`),
		detail:  "Reads SSH private key from home directory.",
	},
	{
		label:   "AWS credentials access",
		pattern: regexp.MustCompile(`\.aws/(credentials|config)`),
		detail:  "Reads AWS credentials file from home directory.",
	},
	{
		label:   "GnuPG keyring access",
		pattern: regexp.MustCompile(`~/\.gnupg/`),
		detail:  "Accesses GnuPG private key material.",
	},
	{
		label:   "GCloud credentials access",
		pattern: regexp.MustCompile(`~/\.config/gcloud/`),
		detail:  "Accesses Google Cloud SDK credentials.",
	},
	{
		label:   "$AWS_SECRET_ACCESS_KEY",
		pattern: regexp.MustCompile(`\$AWS_SECRET_ACCESS_KEY|\$\{AWS_SECRET_ACCESS_KEY\}`),
		detail:  "Reads AWS secret access key from environment.",
	},
	{
		label:   "$GITHUB_TOKEN",
		pattern: regexp.MustCompile(`\$GITHUB_TOKEN|\$\{GITHUB_TOKEN\}`),
		detail:  "Reads GitHub personal access token from environment.",
	},
	{
		label:   "$NPM_TOKEN",
		pattern: regexp.MustCompile(`\$NPM_TOKEN|\$\{NPM_TOKEN\}`),
		detail:  "Reads npm publish token from environment.",
	},
}

func (m *scriptsModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	var findings []Finding

	walkErr := filepath.WalkDir(sc.RepoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			if scriptSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !scriptExtensions[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil || info.Size() > maxScriptSize {
			return nil
		}
		fileFindings, scanErr := scanScriptFile(path, sc.RepoPath, m.Name())
		if scanErr != nil {
			return nil // do not abort the walk on a single file error
		}
		findings = append(findings, fileFindings...)
		return nil
	})

	if walkErr != nil {
		return findings, fmt.Errorf("scripts: walk %s: %w", sc.RepoPath, walkErr)
	}
	return findings, nil
}

// scanScriptFile scans a single file for exfiltration patterns. It reports at
// most one finding per matched pattern label per file to reduce noise.
func scanScriptFile(path, repoPath, moduleName string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scripts: open %s: %w", path, err)
	}
	defer f.Close()

	relPath, _ := filepath.Rel(repoPath, path)
	matched := make(map[string]bool)

	var findings []Finding
	sc := bufio.NewScanner(f)
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := sc.Text()
		for _, pat := range exfiltrationPatterns {
			if matched[pat.label] {
				continue
			}
			if pat.pattern.MatchString(line) {
				matched[pat.label] = true
				findings = append(findings, Finding{
					Severity: Medium,
					Module:   moduleName,
					Path:     relPath,
					Message:  fmt.Sprintf("%s: %s (line %d)", relPath, pat.label, lineNum),
					Detail:   pat.detail,
				})
			}
		}
	}
	return findings, sc.Err()
}
