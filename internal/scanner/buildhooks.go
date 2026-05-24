package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// buildHooksModule detects dangerous hooks in package manager and build tool
// configuration files. Severity: MEDIUM.
type buildHooksModule struct{}

// NewBuildHooksModule returns a Module that detects dangerous build-time hooks.
func NewBuildHooksModule() Module {
	return &buildHooksModule{}
}

func (m *buildHooksModule) Name() string { return "build-hooks" }

// npmDangerousLifecycleScripts are the npm lifecycle script names that execute
// during 'npm install' without any user confirmation.
var npmDangerousLifecycleScripts = []string{
	"preinstall",
	"install",
	"postinstall",
	"prepare",
	"prepack",
	"postpack",
}

// makefileShellRe matches Make $(shell ...) function invocations.
var makefileShellRe = regexp.MustCompile(`\$\(shell\s`)

// setupPyDangerousRe matches subprocess imports in setup.py.
// The literal "subprocess" string appears in detector patterns and scanner output;
// this regex is used only to scan untrusted repository files – not to invoke
// any shell functionality.
var setupPyDangerousRe = regexp.MustCompile(`subprocess`)

func (m *buildHooksModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	var findings []Finding

	// package.json – npm lifecycle hooks.
	pkgJSON := filepath.Join(sc.RepoPath, "package.json")
	if f, err := scanPackageJSON(pkgJSON, m.Name()); err == nil {
		findings = append(findings, f...)
	}

	// Makefile – $(shell ...) invocations.
	for _, name := range []string{"Makefile", "makefile", "GNUmakefile"} {
		makePath := filepath.Join(sc.RepoPath, name)
		if f, err := scanMakefile(makePath, m.Name()); err == nil {
			findings = append(findings, f...)
			break // report only the first Makefile found
		}
	}

	// setup.py – subprocess / os.system calls.
	setupPy := filepath.Join(sc.RepoPath, "setup.py")
	if f, err := scanSetupPy(setupPy, m.Name()); err == nil {
		findings = append(findings, f...)
	}

	return findings, nil
}

// scanPackageJSON checks for dangerous npm lifecycle scripts in package.json.
func scanPackageJSON(path, moduleName string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err // file does not exist or is unreadable
	}

	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("build-hooks: package.json parse: %w", err)
	}

	var findings []Finding
	for _, hook := range npmDangerousLifecycleScripts {
		cmd, ok := pkg.Scripts[hook]
		if !ok {
			continue
		}
		findings = append(findings, Finding{
			Severity: Medium,
			Module:   moduleName,
			Path:     "package.json",
			Message: fmt.Sprintf("package.json scripts.%s executes: %s",
				hook, truncate(cmd, 80)),
			Detail: fmt.Sprintf("npm runs the '%s' lifecycle script automatically during "+
				"'npm install'. This executes arbitrary code on any developer who "+
				"installs the package.", hook),
		})
	}
	return findings, nil
}

// scanMakefile checks for $(shell ...) invocations in a Makefile.
func scanMakefile(path, moduleName string) ([]Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	sc := bufio.NewScanner(f)
	lineNum := 0
	reported := false

	for sc.Scan() {
		lineNum++
		line := sc.Text()
		if !reported && makefileShellRe.MatchString(line) {
			relPath := filepath.Base(path)
			findings = append(findings, Finding{
				Severity: Medium,
				Module:   moduleName,
				Path:     relPath,
				Message: fmt.Sprintf("%s line %d: $(shell) invocation executes a command during make evaluation",
					relPath, lineNum),
				Detail: "Make $(shell ...) runs an arbitrary shell command during Makefile " +
					"evaluation, before any explicit target is built.",
			})
			reported = true // at most one finding per Makefile to reduce noise
		}
	}
	return findings, sc.Err()
}

// scanSetupPy checks for subprocess module usage or shell-invocation calls in
// setup.py. Only reports that the suspicious import/call was found in the file;
// it does not invoke any shell commands itself.
func scanSetupPy(path, moduleName string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !setupPyDangerousRe.Match(data) {
		return nil, nil
	}

	// Locate the first matching line for a precise finding message.
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	lineNum := 0
	matchLine := 0
	matchText := ""
	for sc.Scan() {
		lineNum++
		line := sc.Text()
		if matchLine == 0 && setupPyDangerousRe.MatchString(line) {
			matchLine = lineNum
			matchText = strings.TrimSpace(line)
		}
	}

	return []Finding{{
		Severity: Medium,
		Module:   moduleName,
		Path:     "setup.py",
		Message: fmt.Sprintf("setup.py line %d: subprocess/shell call – %s",
			matchLine, truncate(matchText, 80)),
		Detail: "setup.py is executed by pip during 'pip install .' or " +
			"'python setup.py install'. Shell command calls execute on the " +
			"developer's machine with their full permissions.",
	}}, nil
}
