package intel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store is the local intel cache: a JSONL file of items plus per-source sync state. It is the only thing the
// rest of the platform reads, so a deployment with no network still works with whatever was imported.
type Store struct {
	dir   string
	mu    sync.Mutex
	items map[string]*Item
	State State
}

// State records when each source last synced and what happened.
type State struct {
	Sources map[string]SourceState `json:"sources"`
}

type SourceState struct {
	LastSync string `json:"last_sync"`
	Cursor   string `json:"cursor,omitempty"` // RFC3339: only items modified after this are requested next time
	Items    int    `json:"items"`
	Error    string `json:"error,omitempty"`
}

// Dir returns the default cache directory (override with AVHSOL_INTEL_DIR).
func Dir() string {
	if d := os.Getenv("AVHSOL_INTEL_DIR"); d != "" {
		return d
	}
	return filepath.Join("deploy", "stack", "intel")
}

// Open loads (or creates) the store. The directory is private to the user.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, items: map[string]*Item{}, State: State{Sources: map[string]SourceState{}}}
	if f, err := os.Open(filepath.Join(dir, "items.jsonl")); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
		for sc.Scan() {
			var it Item
			if json.Unmarshal(sc.Bytes(), &it) == nil && it.ID != "" {
				s.items[it.Key()] = &it
			}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("intel cache is damaged: %w", err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil {
		_ = json.Unmarshal(b, &s.State)
		if s.State.Sources == nil {
			s.State.Sources = map[string]SourceState{}
		}
	}
	return s, nil
}

// Upsert merges items in. Enrichment already on a stored item (EPSS, KEV) survives a refresh of the same record.
func (s *Store) Upsert(items []Item) (added, updated int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, it := range items {
		it := it
		it.Clean()
		if it.ID == "" {
			continue
		}
		if old, ok := s.items[it.Key()]; ok {
			if it.EPSS == 0 {
				it.EPSS = old.EPSS
			}
			it.KEV = it.KEV || old.KEV
			it.Aliases = uniq(append(it.Aliases, old.Aliases...))
			if it.Modified != old.Modified || it.Summary != old.Summary || it.KEV != old.KEV {
				updated++
			}
		} else {
			added++
		}
		s.items[it.Key()] = &it
	}
	return
}

// Save writes the cache atomically.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.items))
	for k := range s.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tmp := filepath.Join(s.dir, "items.jsonl.tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, k := range keys {
		if err := enc.Encode(s.items[k]); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, "items.jsonl")); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s.State, "", "  ")
	return os.WriteFile(filepath.Join(s.dir, "state.json"), b, 0o600)
}

// Filter selects items for display, seed generation and report matching.
type Filter struct {
	Source string
	Kind   string
	Tag    string
	Taxon  string
	Query  string
	KEV    bool
	Limit  int
}

// Query returns matching items, most urgent first (KEV, then EPSS, then CVSS, then newest).
func (s *Store) Query(f Filter) []Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := strings.ToLower(f.Query)
	var out []Item
	for _, it := range s.items {
		if f.Source != "" && it.Source != f.Source {
			continue
		}
		if f.Kind != "" && it.Kind != f.Kind {
			continue
		}
		if f.KEV && !it.KEV {
			continue
		}
		if f.Tag != "" && !has(it.Tags, f.Tag) {
			continue
		}
		if f.Taxon != "" && !has(it.Taxon, f.Taxon) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(it.ID+" "+it.Title+" "+it.Summary), q) {
			continue
		}
		out = append(out, *it)
	}
	sort.Slice(out, func(a, b int) bool {
		x, y := out[a], out[b]
		if x.KEV != y.KEV {
			return x.KEV
		}
		if x.EPSS != y.EPSS {
			return x.EPSS > y.EPSS
		}
		if x.CVSS != y.CVSS {
			return x.CVSS > y.CVSS
		}
		if x.Modified != y.Modified {
			return x.Modified > y.Modified
		}
		return x.ID < y.ID
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out
}

// Get returns one item by key or bare id (first match).
func (s *Store) Get(id string) (Item, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if it, ok := s.items[id]; ok {
		return *it, true
	}
	for _, it := range s.items {
		if it.ID == id {
			return *it, true
		}
	}
	return Item{}, false
}

// Count returns the number of stored items.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// SetState records a source's sync result.
func (s *Store) SetState(name string, st SourceState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State.Sources[name] = st
}

// Cursor returns when a source last saw data (zero time = never).
func (s *Store) Cursor(name string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, _ := time.Parse(time.RFC3339, s.State.Sources[name].Cursor)
	return t
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
