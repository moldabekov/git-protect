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

// configEntry represents one key=value pair parsed from the INI config, with
// its fully qualified key name (section.subsection.key or section.key).
type configEntry struct {
	qualifiedKey string // e.g. "core.fsmonitor", "filter.lfs.smudge"
	value        string
}

// configModule scans .git/config for directives that cause git to execute
// arbitrary commands or redirect traffic to attacker-controlled infrastructure.
type configModule struct{}

// NewConfigModule returns a Module that detects dangerous .git/config keys.
func NewConfigModule() Module {
	return &configModule{}
}

func (c *configModule) Name() string { return "config" }

func (c *configModule) Scan(_ context.Context, sc ScanContext) ([]Finding, error) {
	cfgPath := filepath.Join(sc.RepoPath, ".git", "config")
	f, err := os.Open(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("config: open %s: %w", cfgPath, err)
	}
	defer f.Close()

	entries, err := parseGitConfig(f)
	if err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", cfgPath, err)
	}

	relPath := filepath.Join(".git", "config")
	var findings []Finding
	for _, entry := range entries {
		if msg, detail := checkDangerous(entry); msg != "" {
			findings = append(findings, Finding{
				Severity: Critical,
				Module:   "config",
				Path:     relPath,
				Message:  msg,
				Detail:   detail,
			})
		}
	}
	return findings, nil
}

// parseGitConfig parses git INI format from r and returns all key=value entries
// with fully-qualified key names.
//
// Git INI grammar:
//
//	[section]           -> section.key
//	[section "sub"]     -> section.sub.key  (subsection is case-sensitive)
//	key = value
//	# and ; are comment characters
func parseGitConfig(r io.Reader) ([]configEntry, error) {
	sc := bufio.NewScanner(r)
	var entries []configEntry
	var section string    // lowercased section name
	var subsection string // exact-case subsection (between double quotes)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			// Section header: [section] or [section "subsection"]
			end := strings.LastIndex(line, "]")
			if end < 0 {
				continue
			}
			header := line[1:end]
			if idx := strings.Index(header, `"`); idx >= 0 {
				section = strings.ToLower(strings.TrimSpace(header[:idx]))
				sub := header[idx:]
				sub = strings.Trim(sub, ` "`)
				subsection = sub
			} else {
				section = strings.ToLower(strings.TrimSpace(header))
				subsection = ""
			}
			continue
		}
		// Key=value line.
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		val = stripInlineComment(val)
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}

		var qualKey string
		if subsection != "" {
			qualKey = section + "." + subsection + "." + key
		} else {
			qualKey = section + "." + key
		}
		entries = append(entries, configEntry{qualifiedKey: qualKey, value: val})
	}
	return entries, sc.Err()
}

// stripInlineComment removes an unquoted # or ; comment from the end of a value.
func stripInlineComment(s string) string {
	inQuote := false
	for i, ch := range s {
		switch ch {
		case '"':
			inQuote = !inQuote
		case '#', ';':
			if !inQuote {
				return strings.TrimSpace(s[:i])
			}
		}
	}
	return s
}

// checkDangerous inspects one config entry and returns (message, detail) if the
// entry is dangerous. Returns ("", "") if safe.
func checkDangerous(e configEntry) (string, string) { //nolint:cyclop
	k := e.qualifiedKey
	v := e.value

	hasSection := func(sec string) bool { return strings.HasPrefix(k, sec+".") }
	hasSuffix := func(suf string) bool { return strings.HasSuffix(k, "."+suf) }

	switch {
	case k == "core.fsmonitor":
		return "core.fsmonitor",
			"Runs an arbitrary shell command on every 'git status'. " +
				"IDEs trigger git status automatically. Value: " + v

	case k == "core.pager":
		return "core.pager",
			"Runs a shell pipeline to page output of git log/diff/show. Value: " + v

	case k == "core.editor":
		return "core.editor",
			"Replaces the editor launched for git commit and git rebase -i. Value: " + v

	case k == "core.sshcommand":
		return "core.sshCommand",
			"Replaces the SSH binary used for all remote operations. Value: " + v

	case k == "core.askpass":
		return "core.askPass",
			"Runs an arbitrary program to supply credentials. Value: " + v

	case k == "core.hookspath":
		return "core.hooksPath",
			"Redirects all hook lookups to an attacker-controlled directory. Value: " + v

	case k == "core.gitproxy":
		return "core.gitProxy",
			"Specifies a command run as proxy for git:// protocol connections. Value: " + v

	case k == "core.alternaterefscommand":
		return "core.alternateRefsCommand",
			"Shell command executed when advertising alternate refs. Value: " + v

	case k == "credential.helper":
		return "credential.helper",
			"Runs an arbitrary program to supply or store credentials. Value: " + v

	case hasSection("diff") && hasSuffix("textconv"):
		return k,
			"Runs an arbitrary program to convert file content for diff output. Value: " + v

	case k == "diff.external":
		return "diff.external",
			"Replaces the diff program with an arbitrary shell command. Value: " + v

	case hasSection("difftool") && hasSuffix("cmd"):
		return k,
			"Shell command run by git difftool. Value: " + v

	case k == "merge.tool":
		return "merge.tool",
			"Specifies the merge tool; combined with mergetool.<name>.cmd this " +
				"executes arbitrary commands. Value: " + v

	case hasSection("mergetool") && hasSuffix("cmd"):
		return k,
			"Shell command run by git mergetool. Value: " + v

	case hasSection("filter") && hasSuffix("smudge"):
		return k,
			"Runs an arbitrary program on every file during git checkout. Value: " + v

	case hasSection("filter") && hasSuffix("clean"):
		return k,
			"Runs an arbitrary program on every file during git add. Value: " + v

	case hasSection("filter") && hasSuffix("process"):
		return k,
			"Runs a persistent arbitrary process handling all filter operations. Value: " + v

	case hasSection("alias"):
		if strings.HasPrefix(v, "!") {
			return k,
				"Alias with '!' prefix executes a shell command on 'git <alias>'. Value: " + v
		}

	case k == "gpg.program":
		return "gpg.program",
			"Replaces the GPG binary for signing operations. Value: " + v

	case hasSection("gpg") && hasSuffix("program"):
		return k,
			"Replaces a GPG variant binary for signing operations. Value: " + v

	case k == "gpg.ssh.defaultkeycommand":
		return "gpg.ssh.defaultKeyCommand",
			"Shell command executed to look up the default SSH signing key. Value: " + v

	case k == "sequence.editor":
		return "sequence.editor",
			"Replaces the editor used for interactive rebase. Value: " + v

	case hasSection("trailer") && hasSuffix("command"):
		return k,
			"Shell command executed by git interpret-trailers. Value: " + v

	case hasSection("trailer") && hasSuffix("cmd"):
		return k,
			"Shell command executed by git interpret-trailers. Value: " + v

	case hasSection("remote") && hasSuffix("uploadpack"):
		return k,
			"Specifies the upload-pack command for git fetch. Value: " + v

	case hasSection("remote") && hasSuffix("receivepack"):
		return k,
			"Specifies the receive-pack command for git push. Value: " + v

	case hasSection("url") && hasSuffix("insteadof"):
		// Reconstruct a display key preserving the url subsection.
		parts := strings.SplitN(k, ".", 3)
		displayKey := k
		if len(parts) == 3 {
			displayKey = "url." + parts[1] + ".insteadOf"
		}
		return displayKey,
			"Silently rewrites remote URLs to attacker-controlled servers. Value: " + v

	case k == "http.sslcainfo":
		return "http.sslCAInfo",
			"Overrides the CA certificate store, enabling MITM on HTTPS git operations. Value: " + v

	case k == "http.sslverify":
		if isDisabled(v) {
			return "http.sslVerify",
				"Disables TLS certificate verification, enabling MITM on HTTPS git operations."
		}

	case k == "http.proxy":
		return "http.proxy",
			"Redirects all HTTPS git traffic through an attacker-controlled proxy. Value: " + v

	case k == "sendemail.smtpserver":
		return "sendemail.smtpserver",
			"Redirects git send-email through an attacker-controlled SMTP server. Value: " + v
	}

	return "", ""
}

// isDisabled returns true if v represents a false/disabled boolean.
func isDisabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "0", "off", "no":
		return true
	}
	return false
}
