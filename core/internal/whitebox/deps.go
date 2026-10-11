package whitebox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/41vi4p/avhsol/core/internal/intel"
)

var (
	reqLine  = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(==|>=|~=|<=|>|<|!=)?\s*([A-Za-z0-9.*+!_\-]*)`)
	goReq    = regexp.MustCompile(`^\s*([\w./\-~]+)\s+(v[\w.+\-]+)`)
	exactVer = regexp.MustCompile(`^\d+(\.\d+)*([\-+.][0-9A-Za-z.\-+]+)?$`)
)

// parseDeps lists dependencies from manifests and lock files. Exact versions come from lock files and pinned requirements.
func parseDeps(other map[string]string) []Dep {
	seen := map[string]Dep{}
	add := func(d Dep) {
		k := d.Ecosystem + "|" + d.Name
		if old, ok := seen[k]; ok {
			if old.Version != "" || d.Version == "" {
				if d.Direct {
					old.Direct = true
					seen[k] = old
				}
				return
			}
		}
		seen[k] = d
	}
	for rel, txt := range other {
		switch b := baseName(rel); {
		case b == "package.json":
			var pj struct {
				Dependencies map[string]string `json:"dependencies"`
				Dev          map[string]string `json:"devDependencies"`
			}
			if json.Unmarshal([]byte(txt), &pj) == nil {
				for _, m := range []map[string]string{pj.Dependencies, pj.Dev} {
					for n, v := range m {
						ver := strings.TrimLeft(v, "^~=v ")
						if !exactVer.MatchString(ver) {
							ver = ""
						}
						add(Dep{Ecosystem: "npm", Name: n, Version: ver, File: rel, Direct: true})
					}
				}
			}
		case b == "package-lock.json":
			var lock struct {
				Packages map[string]struct {
					Version string `json:"version"`
				} `json:"packages"`
				Dependencies map[string]struct {
					Version string `json:"version"`
				} `json:"dependencies"`
			}
			if json.Unmarshal([]byte(txt), &lock) == nil {
				for p, v := range lock.Packages {
					if i := strings.LastIndex(p, "node_modules/"); i >= 0 && v.Version != "" {
						add(Dep{Ecosystem: "npm", Name: p[i+len("node_modules/"):], Version: v.Version, File: rel})
					}
				}
				for n, v := range lock.Dependencies {
					if v.Version != "" {
						add(Dep{Ecosystem: "npm", Name: n, Version: v.Version, File: rel})
					}
				}
			}
		case strings.HasPrefix(b, "requirements") && strings.HasSuffix(b, ".txt"):
			for _, ln := range strings.Split(txt, "\n") {
				ln = strings.TrimSpace(strings.SplitN(ln, "#", 2)[0])
				if ln == "" || strings.HasPrefix(ln, "-") {
					continue
				}
				if m := reqLine.FindStringSubmatch(ln); m != nil {
					ver := ""
					if m[3] == "==" && exactVer.MatchString(m[4]) {
						ver = m[4]
					}
					add(Dep{Ecosystem: "PyPI", Name: strings.ToLower(m[1]), Version: ver, File: rel, Direct: true})
				}
			}
		case b == "pyproject.toml":
			for _, m := range regexp.MustCompile(`(?m)^\s*"([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*(==|>=|~=|<=|>|<)?\s*([0-9][^",;]*)?`).FindAllStringSubmatch(txt, -1) {
				ver := ""
				if m[2] == "==" && exactVer.MatchString(strings.TrimSpace(m[3])) {
					ver = strings.TrimSpace(m[3])
				}
				add(Dep{Ecosystem: "PyPI", Name: strings.ToLower(m[1]), Version: ver, File: rel, Direct: true})
			}
		case b == "poetry.lock" || b == "uv.lock":
			for _, m := range regexp.MustCompile(`(?m)^name = "([^"]+)"\nversion = "([^"]+)"`).FindAllStringSubmatch(txt, -1) {
				add(Dep{Ecosystem: "PyPI", Name: strings.ToLower(m[1]), Version: m[2], File: rel})
			}
		case b == "go.mod":
			inBlock := false
			for _, ln := range strings.Split(txt, "\n") {
				t := strings.TrimSpace(ln)
				if strings.HasPrefix(t, "require (") {
					inBlock = true
					continue
				}
				if t == ")" {
					inBlock = false
					continue
				}
				t = strings.TrimPrefix(t, "require ")
				if inBlock || strings.HasPrefix(strings.TrimSpace(ln), "require ") {
					if m := goReq.FindStringSubmatch(t); m != nil {
						add(Dep{Ecosystem: "Go", Name: m[1], Version: strings.TrimPrefix(m[2], "v"), File: rel, Direct: !strings.Contains(t, "// indirect")})
					}
				}
			}
		case b == "Cargo.lock":
			for _, m := range regexp.MustCompile(`(?m)^name = "([^"]+)"\nversion = "([^"]+)"`).FindAllStringSubmatch(txt, -1) {
				add(Dep{Ecosystem: "crates.io", Name: m[1], Version: m[2], File: rel})
			}
		}
	}
	out := make([]Dep, 0, len(seen))
	for _, d := range seen {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// OSV is the minimal client for the exact-version vulnerability query.
type OSV struct {
	Base   string // default https://api.osv.dev
	Client *http.Client
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

// Query asks OSV which of the dependencies (those with an exact version) have known advisories. Only package
// names and versions leave the machine, over HTTPS.
func (o *OSV) Query(ctx context.Context, deps []Dep) ([]DepFinding, error) {
	base := o.Base
	if base == "" {
		base = "https://api.osv.dev"
	}
	if !strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://127.0.0.1") && !strings.HasPrefix(base, "http://localhost") {
		return nil, fmt.Errorf("OSV base must be https")
	}
	cl := o.Client
	if cl == nil {
		cl = &http.Client{Timeout: 60 * time.Second}
	}
	var pinned []Dep
	for _, d := range deps {
		if d.Version != "" {
			pinned = append(pinned, d)
		}
	}
	var out []DepFinding
	const batch = 400
	for i := 0; i < len(pinned); i += batch {
		end := i + batch
		if end > len(pinned) {
			end = len(pinned)
		}
		chunk := pinned[i:end]
		qs := make([]osvQuery, len(chunk))
		for j, d := range chunk {
			qs[j].Package.Name, qs[j].Package.Ecosystem, qs[j].Version = d.Name, d.Ecosystem, d.Version
		}
		body, _ := json.Marshal(map[string]any{"queries": qs})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/v1/querybatch", bytes.NewReader(body))
		if err != nil {
			return out, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := cl.Do(req)
		if err != nil {
			return out, err
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return out, fmt.Errorf("OSV answered %d", resp.StatusCode)
		}
		var res struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := json.Unmarshal(raw, &res); err != nil {
			return out, err
		}
		for j, r := range res.Results {
			if j >= len(chunk) || len(r.Vulns) == 0 {
				continue
			}
			f := DepFinding{Dep: chunk[j], Exact: true}
			for _, v := range r.Vulns {
				f.IDs = append(f.IDs, v.ID)
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// enrich links advisories to the local threat-intel cache (severity, KEV, EPSS) when it has them.
func enrich(finds []DepFinding, st *intel.Store) []DepFinding {
	if st == nil {
		return finds
	}
	for i := range finds {
		for _, id := range finds[i].IDs {
			for _, src := range []string{"ghsa", "osv", "nvd"} {
				if it, ok := st.Get(src + ":" + id); ok {
					if finds[i].Summary == "" {
						finds[i].Summary = it.Title
					}
					if finds[i].Severity == "" {
						finds[i].Severity = it.Severity
					}
					finds[i].KEV = finds[i].KEV || it.KEV
					if it.EPSS > finds[i].EPSS {
						finds[i].EPSS = it.EPSS
					}
				}
			}
		}
	}
	return finds
}

// nameOnly compares package names with the local cache's affected packages (no versions: possible matches only).
func nameOnly(deps []Dep, st *intel.Store) []DepFinding {
	if st == nil {
		return nil
	}
	items := st.Query(intel.Filter{})
	idx := map[string][]intel.Item{}
	for _, it := range items {
		for _, a := range it.Affects {
			idx[strings.ToLower(a)] = append(idx[strings.ToLower(a)], it)
		}
	}
	eco := map[string]string{"npm": "npm", "PyPI": "pypi", "Go": "go", "crates.io": "crates.io"}
	var out []DepFinding
	for _, d := range deps {
		if !d.Direct {
			continue
		}
		hits := idx[strings.ToLower(eco[d.Ecosystem]+":"+d.Name)]
		if len(hits) == 0 {
			continue
		}
		f := DepFinding{Dep: d}
		for _, it := range hits {
			f.IDs = append(f.IDs, it.ID)
			f.KEV = f.KEV || it.KEV
			if it.EPSS > f.EPSS {
				f.EPSS = it.EPSS
			}
			if f.Summary == "" {
				f.Summary = it.Title
			}
			if f.Severity == "" || sevOrder[it.Severity] < sevOrder[f.Severity] {
				f.Severity = it.Severity
			}
		}
		if len(f.IDs) > 6 {
			f.IDs = f.IDs[:6]
		}
		out = append(out, f)
	}
	return out
}
