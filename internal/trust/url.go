package trust

import (
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Normalize converts any git URL form into a canonical host/path string
// suitable for trust-store matching. The returned string has no scheme,
// no trailing slash, no .git suffix, and no user@ prefix.
// Returns ("", false) for local paths (file:// or bare /path).
func Normalize(raw string) (string, bool) {
	if IsLocalPath(raw) {
		return "", false
	}

	// Handle SCP-style SSH: git@github.com:org/repo.git
	if !strings.Contains(raw, "://") && strings.Contains(raw, ":") {
		// Must look like user@host:path or host:path
		atIdx := strings.Index(raw, "@")
		colonIdx := strings.Index(raw, ":")
		if atIdx < colonIdx {
			// has user@host:path form
			hostPart := raw[atIdx+1 : colonIdx]
			pathPart := raw[colonIdx+1:]
			return normalizeParts(hostPart, pathPart), true
		} else if atIdx == -1 {
			// host:path with no user
			hostPart := raw[:colonIdx]
			pathPart := raw[colonIdx+1:]
			return normalizeParts(hostPart, pathPart), true
		}
	}

	// Parse as standard URL
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}

	host := u.Hostname()
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)

	// Strip default ports
	if (scheme == "https" && port == "443") ||
		(scheme == "http" && port == "80") ||
		(scheme == "ssh" && port == "22") ||
		(scheme == "git" && port == "9418") {
		port = ""
	}

	if port != "" {
		host = net.JoinHostPort(host, port)
	}

	return normalizeParts(host, u.Path), true
}

// normalizeParts cleans host and path and joins them.
func normalizeParts(host, path string) string {
	host = normalizeHost(host)
	path = normalizePath(path)
	if path == "" {
		return host
	}
	return host + "/" + path
}

// normalizeHost lowercases, punycode-decodes IDN, strips user@ if present.
func normalizeHost(host string) string {
	// Strip user@ if sneaked in
	if idx := strings.Index(host, "@"); idx != -1 {
		host = host[idx+1:]
	}
	host = strings.ToLower(strings.TrimSpace(host))

	// Normalize to ASCII (punycode) to prevent homograph attacks
	// (e.g. gíthub.com must not match github.com).
	if p, err := idna.Lookup.ToASCII(host); err == nil {
		host = p
	}
	return host
}

// normalizePath strips leading slash, .git suffix, trailing slash,
// and percent-decodes segments.
func normalizePath(path string) string {
	// Percent-decode
	if dec, err := url.PathUnescape(path); err == nil && utf8.ValidString(dec) {
		path = dec
	}

	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")
	path = strings.TrimSuffix(path, ".git")
	path = strings.TrimSuffix(path, "/") // in case ".git/" had trailing slash

	// Collapse any double slashes
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}

	return path
}

// IsLocalPath returns true for file:// URLs and bare filesystem paths
// (absolute paths starting with /, relative paths, or paths with no host).
func IsLocalPath(raw string) bool {
	if strings.HasPrefix(raw, "file://") {
		return true
	}
	// Absolute path
	if strings.HasPrefix(raw, "/") {
		return true
	}
	// Relative paths like ./foo or ../bar
	if strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") {
		return true
	}
	// filepath.IsAbs handles Windows C:\ etc.
	if filepath.IsAbs(raw) {
		return true
	}
	// Has no scheme and looks like a bare path (no dot-com host)
	if !strings.Contains(raw, "://") && !strings.Contains(raw, ":") && !strings.Contains(raw, ".") {
		return true
	}
	return false
}
