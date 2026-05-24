package trust_test

import (
	"testing"

	"github.com/moldabekov/git-protect/internal/trust"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		url     string
		pattern string
		want    bool
	}{
		// Exact matches
		{"github.com/org/repo", "github.com/org/repo", true},
		{"github.com/org/repo", "github.com/org/other", false},
		{"github.com/org/repo", "github.com/org/rep", false},
		// Org wildcard
		{"github.com/myorg/repo", "github.com/myorg/*", true},
		{"github.com/myorg/another", "github.com/myorg/*", true},
		{"github.com/myorg", "github.com/myorg/*", true}, // prefix itself
		{"github.com/other/repo", "github.com/myorg/*", false},
		// Host wildcard
		{"gitlab.internal.corp/team/repo", "gitlab.internal.corp/*", true},
		{"gitlab.internal.corp/a/b/c", "gitlab.internal.corp/*", true},
		{"evil.corp/team/repo", "gitlab.internal.corp/*", false},
		// Case insensitivity
		{"GITHUB.COM/Org/Repo", "github.com/org/repo", true},
		// Wildcard must not match cross-host
		{"evilgithub.com/myorg/repo", "github.com/myorg/*", false},
	}

	for _, tt := range tests {
		got := trust.Match(tt.url, tt.pattern)
		if got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.url, tt.pattern, got, tt.want)
		}
	}
}
