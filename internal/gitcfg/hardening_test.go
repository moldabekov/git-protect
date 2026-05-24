package gitcfg_test

import (
	"testing"

	"github.com/moldabekov/git-protect/internal/gitcfg"
)

func TestHardeningEntries_Count(t *testing.T) {
	entries := gitcfg.HardeningEntries()
	if len(entries) != 6 {
		t.Errorf("HardeningEntries() returned %d entries, want 6", len(entries))
	}
}

func TestHardeningEntries_Keys(t *testing.T) {
	entries := gitcfg.HardeningEntries()
	expected := map[string]bool{
		"core.hooksPath":       true,
		"safe.bareRepository":  true,
		"core.fsmonitor":       true,
		"transfer.fsckObjects": true,
		"core.protectHFS":      true,
		"core.protectNTFS":     true,
	}
	for _, e := range entries {
		if !expected[e.Key] {
			t.Errorf("unexpected key %q in hardening entries", e.Key)
		}
		delete(expected, e.Key)
	}
	for missing := range expected {
		t.Errorf("missing key %q in hardening entries", missing)
	}
}

func TestHardeningEntries_OverridableFlags(t *testing.T) {
	entries := gitcfg.HardeningEntries()
	byKey := make(map[string]gitcfg.ConfigEntry)
	for _, e := range entries {
		byKey[e.Key] = e
	}

	// Only safe.bareRepository is NOT overridable (protected config)
	if byKey["safe.bareRepository"].Overridable {
		t.Error("safe.bareRepository should not be overridable (protected config)")
	}
	// All others should be overridable (best-effort)
	overridable := []string{
		"core.hooksPath",
		"core.fsmonitor",
		"transfer.fsckObjects",
		"core.protectHFS",
		"core.protectNTFS",
	}
	for _, key := range overridable {
		if !byKey[key].Overridable {
			t.Errorf("%s should be overridable", key)
		}
	}
}

func TestHardeningEntries_PurposeNonEmpty(t *testing.T) {
	for _, e := range gitcfg.HardeningEntries() {
		if e.Purpose == "" {
			t.Errorf("entry %q has empty Purpose", e.Key)
		}
	}
}

func TestHardeningEntries_ValuesSet(t *testing.T) {
	entries := gitcfg.HardeningEntries()
	byKey := make(map[string]gitcfg.ConfigEntry)
	for _, e := range entries {
		byKey[e.Key] = e
	}
	// Entries with known values
	checks := map[string]string{
		"safe.bareRepository":  "explicit",
		"core.fsmonitor":       "false",
		"transfer.fsckObjects": "true",
		"core.protectHFS":      "true",
		"core.protectNTFS":     "true",
	}
	for key, want := range checks {
		if got := byKey[key].Value; got != want {
			t.Errorf("entry %q value = %q, want %q", key, got, want)
		}
	}
}
