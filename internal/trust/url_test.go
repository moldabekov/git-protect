package trust_test

import (
	"testing"

	"github.com/moldabekov/git-protect/internal/trust"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
		wantOK bool
	}{
		// HTTPS variants
		{
			name:   "https basic",
			input:  "https://github.com/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "https no git suffix",
			input:  "https://github.com/org/repo",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "https trailing slash",
			input:  "https://github.com/org/repo/",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "https with default port 443",
			input:  "https://github.com:443/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "https with non-default port",
			input:  "https://github.com:8443/org/repo.git",
			want:   "github.com:8443/org/repo",
			wantOK: true,
		},
		// SSH variants
		{
			name:   "ssh scp style git@",
			input:  "git@github.com:org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "ssh scp no user",
			input:  "github.com:org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "ssh:// url",
			input:  "ssh://git@github.com/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		{
			name:   "ssh:// with default port 22",
			input:  "ssh://github.com:22/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		// git:// protocol
		{
			name:   "git protocol",
			input:  "git://github.com/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		// http
		{
			name:   "http basic",
			input:  "http://github.com/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		// Local paths – must return false
		{
			name:   "file:// scheme",
			input:  "file:///home/user/repo",
			want:   "",
			wantOK: false,
		},
		{
			name:   "absolute path",
			input:  "/home/user/repo",
			want:   "",
			wantOK: false,
		},
		{
			name:   "relative path dot-slash",
			input:  "./myrepo",
			want:   "",
			wantOK: false,
		},
		{
			name:   "relative path dot-dot",
			input:  "../sibling",
			want:   "",
			wantOK: false,
		},
		// Percent encoding
		{
			name:   "percent-encoded path",
			input:  "https://github.com/org/my%2Drepo.git",
			want:   "github.com/org/my-repo",
			wantOK: true,
		},
		// Case insensitivity of host
		{
			name:   "uppercase host",
			input:  "https://GITHUB.COM/org/repo.git",
			want:   "github.com/org/repo",
			wantOK: true,
		},
		// Nested path (deep)
		{
			name:   "gitlab subgroup",
			input:  "https://gitlab.com/group/subgroup/repo.git",
			want:   "gitlab.com/group/subgroup/repo",
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := trust.Normalize(tt.input)
			if ok != tt.wantOK {
				t.Errorf("Normalize(%q) ok=%v, want %v", tt.input, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("Normalize(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsLocalPath(t *testing.T) {
	locals := []string{
		"/home/user/repo",
		"./repo",
		"../repo",
		"file:///tmp/repo",
	}
	nonLocals := []string{
		"https://github.com/org/repo",
		"git@github.com:org/repo.git",
		"ssh://github.com/org/repo",
	}

	for _, p := range locals {
		if !trust.IsLocalPath(p) {
			t.Errorf("IsLocalPath(%q) = false, want true", p)
		}
	}
	for _, p := range nonLocals {
		if trust.IsLocalPath(p) {
			t.Errorf("IsLocalPath(%q) = true, want false", p)
		}
	}
}
