package trust

import "strings"

// MatchAny returns true if normalizedURL matches at least one trust entry.
func MatchAny(normalizedURL string, entries []Entry) bool {
	for _, e := range entries {
		if Match(normalizedURL, e.Pattern) {
			return true
		}
	}
	return false
}

// Match checks whether normalizedURL matches the given pattern.
//
// Pattern types (inferred from the pattern string itself):
//
//   - Exact match:   "github.com/org/repo"   — matches only that repo
//   - Org wildcard:  "github.com/org/*"       — matches any repo under org
//   - Host wildcard: "github.com/*"           — matches all repos on host
//
// Both normalizedURL and pattern are already normalized (lowercase, no scheme,
// no .git suffix). The function is case-insensitive as an additional safety net.
func Match(normalizedURL, pattern string) bool {
	u := strings.ToLower(normalizedURL)
	pat := strings.ToLower(pattern)

	if !strings.HasSuffix(pat, "/*") {
		// Exact match
		return u == pat
	}

	// Prefix match: strip trailing "/*" and check that url starts with prefix + "/"
	// or equals the prefix exactly.
	prefix := strings.TrimSuffix(pat, "/*")
	return u == prefix || strings.HasPrefix(u, prefix+"/")
}
