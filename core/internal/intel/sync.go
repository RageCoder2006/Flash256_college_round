package intel

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed data/watchlist.yaml
var watchlistYAML []byte

//go:embed data/feeds.yaml
var feedsYAML []byte

// SourceResult is what one source did in a sync.
type SourceResult struct {
	Source  string `json:"source"`
	Fetched int    `json:"fetched"`
	Added   int    `json:"added"`
	Updated int    `json:"updated"`
	Error   string `json:"error,omitempty"`
}

// Report is the outcome of a sync, written to the audit log.
type Report struct {
	At      string         `json:"at"`
	Results []SourceResult `json:"results"`
	Total   int            `json:"total_items"`
}

// Syncer is the only component that talks to the network. It is run explicitly; nothing calls it during a test run.
type Syncer struct {
	Store     *Store
	Client    *Client
	Sources   []Source
	Enrichers []Enricher
	Tax       *Taxonomy
	Now       func() time.Time
}

// Run syncs the named sources (all if names is empty), then runs the enrichers. A failing source is recorded and
// skipped; it never stops the others and never discards what the cache already holds.
func (s *Syncer) Run(ctx context.Context, names []string) Report {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	want := map[string]bool{}
	for _, n := range names {
		want[strings.TrimSpace(n)] = true
	}
	rep := Report{At: now().UTC().Format(time.RFC3339)}
	for _, src := range s.Sources {
		if len(want) > 0 && !want[src.Name()] {
			continue
		}
		start := now().UTC()
		items, err := src.Fetch(ctx, s.Client, s.Store.Cursor(src.Name()))
		res := SourceResult{Source: src.Name(), Fetched: len(items)}
		for i := range items {
			if s.Tax != nil {
				s.Tax.Annotate(&items[i])
			}
		}
		res.Added, res.Updated = s.Store.Upsert(items)
		st := s.Store.State.Sources[src.Name()]
		st.LastSync = start.Format(time.RFC3339)
		st.Items += res.Added
		if err != nil {
			res.Error = err.Error()
			st.Error = res.Error
		} else {
			st.Error = ""
			st.Cursor = start.Format(time.RFC3339)
		}
		s.Store.SetState(src.Name(), st)
		rep.Results = append(rep.Results, res)
	}
	for _, e := range s.Enrichers {
		if len(want) > 0 && !want[e.Name()] {
			continue
		}
		n, err := e.Enrich(ctx, s.Client, s.Store)
		r := SourceResult{Source: e.Name(), Updated: n}
		if err != nil {
			r.Error = err.Error()
		}
		st := s.Store.State.Sources[e.Name()]
		st.LastSync, st.Error = now().UTC().Format(time.RFC3339), r.Error
		s.Store.SetState(e.Name(), st)
		rep.Results = append(rep.Results, r)
	}
	rep.Total = s.Store.Count()
	return rep
}

// Defaults builds the standard source set. Tokens come from the environment only. A watchlist.yaml or feeds.yaml
// in the intel directory overrides the built-in one.
func Defaults(dir string) (*Syncer, error) {
	st, err := Open(dir)
	if err != nil {
		return nil, err
	}
	tax, err := LoadTaxonomy()
	if err != nil {
		return nil, err
	}
	var wl Watchlist
	b := watchlistYAML
	if o, ok := readFileIf(filepath.Join(dir, "watchlist.yaml")); ok {
		b = o
	}
	if err := yaml.Unmarshal(b, &wl); err != nil {
		return nil, fmt.Errorf("watchlist: %w", err)
	}
	var fl struct {
		Feeds []FeedSpec `yaml:"feeds"`
	}
	fb := feedsYAML
	if o, ok := readFileIf(filepath.Join(dir, "feeds.yaml")); ok {
		fb = o
	}
	if err := yaml.Unmarshal(fb, &fl); err != nil {
		return nil, fmt.Errorf("feeds: %w", err)
	}
	c := NewClient()
	nvdKey := os.Getenv("AVHSOL_NVD_API_KEY")
	nvdPause := 6 * time.Second // 5 requests per 30 s without a key
	if nvdKey != "" {
		nvdPause = 700 * time.Millisecond
	}
	return &Syncer{Store: st, Client: c, Tax: tax,
		Sources: []Source{
			&GHSA{Token: os.Getenv("AVHSOL_GITHUB_TOKEN"), Watch: &wl, Pause: 300 * time.Millisecond},
			&NVD{APIKey: nvdKey, Pause: nvdPause},
			&OSV{Watch: &wl, Pause: 100 * time.Millisecond, MaxDetails: 120},
			&Feeds{Feeds: fl.Feeds},
		},
		Enrichers: []Enricher{&KEV{}, &EPSS{}},
	}, nil
}
