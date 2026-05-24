package trust

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// Entry represents one row in the trust store.
type Entry struct {
	Pattern string    `toml:"pattern"`
	Type    string    `toml:"type"` // "repo", "org", "host"
	Added   time.Time `toml:"added"`
	Note    string    `toml:"note,omitempty"`
}

// trustFile is the on-disk TOML structure.
type trustFile struct {
	Trust []Entry `toml:"trust"`
}

// Store manages the TOML trust store with strict security invariants.
type Store struct {
	path string
}

// NewStore creates a Store for the given path. The path need not exist yet.
func NewStore(path string) *Store {
	return &Store{path: path}
}

// Load reads and validates the trust store from disk.
// Returns an empty list if the file does not exist yet.
// Returns an error if:
//   - the path is a symlink
//   - the file permissions are not exactly 0600
//   - TOML parsing fails
func (s *Store) Load() ([]Entry, error) {
	// Symlink check via Lstat (does not follow symlinks).
	info, err := os.Lstat(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("trust store stat: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("trust store %q is a symlink – refusing to load (security policy)", s.path)
	}
	if info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("trust store %q has unsafe permissions %04o – expected 0600", s.path, info.Mode().Perm())
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("trust store read: %w", err)
	}

	var tf trustFile
	if err := toml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("trust store parse: %w", err)
	}
	return tf.Trust, nil
}

// Add appends a new entry to the trust store. Idempotent: if an entry with
// the same pattern already exists, Add returns nil without writing.
func (s *Store) Add(e Entry) error {
	entries, err := s.Load()
	if err != nil {
		return err
	}
	// Deduplicate by pattern.
	for _, existing := range entries {
		if existing.Pattern == e.Pattern {
			return nil
		}
	}
	if e.Added.IsZero() {
		e.Added = time.Now().UTC().Truncate(24 * time.Hour)
	}
	entries = append(entries, e)
	return s.save(entries)
}

// Remove deletes an entry by pattern. Returns nil if the pattern was not found.
func (s *Store) Remove(pattern string) error {
	entries, err := s.Load()
	if err != nil {
		return err
	}
	filtered := entries[:0]
	for _, e := range entries {
		if e.Pattern != pattern {
			filtered = append(filtered, e)
		}
	}
	return s.save(filtered)
}

// IsTrusted returns true if the normalized form of rawURL matches any entry.
// Local paths always return false.
func (s *Store) IsTrusted(rawURL string) (bool, error) {
	norm, ok := Normalize(rawURL)
	if !ok {
		return false, nil
	}
	entries, err := s.Load()
	if err != nil {
		return false, err
	}
	return MatchAny(norm, entries), nil
}

// save writes entries atomically: temp file → fsync → rename.
func (s *Store) save(entries []Entry) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("trust store mkdir: %w", err)
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".trust-*.toml.tmp")
	if err != nil {
		return fmt.Errorf("trust store temp create: %w", err)
	}
	tmpName := tmp.Name()

	// Clean up temp file on any error path.
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	// Set 0600 before writing any data.
	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("trust store chmod: %w", err)
	}

	tf := trustFile{Trust: entries}
	enc := toml.NewEncoder(tmp)
	if err := enc.Encode(tf); err != nil {
		return fmt.Errorf("trust store encode: %w", err)
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("trust store fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("trust store close: %w", err)
	}

	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("trust store rename: %w", err)
	}
	ok = true
	return nil
}
