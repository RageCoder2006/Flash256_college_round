package tui

import (
	"context"
	"fmt"
	"github.com/41vi4p/avhsol/core/internal/home"
	"os"
	"time"

	"github.com/41vi4p/avhsol/core/internal/cliagent"
	"github.com/41vi4p/avhsol/core/internal/export"
	"github.com/41vi4p/avhsol/core/internal/graph"
	"github.com/41vi4p/avhsol/core/internal/guard"
	"github.com/41vi4p/avhsol/core/internal/intel"
	"github.com/41vi4p/avhsol/core/internal/sign"
)

// Check is one line of the Doctor screen: what was checked, how it went, and what to do about it.
type Check struct {
	Label  string
	State  string // ok | warn | bad | off
	Detail string
	Fix    string
}

func signingKey() string { return graph.Setting("AVHSOL_SIGNING_KEY", "", home.SigningKey()) }

// GuardURL is where the guard proxy is expected.
func GuardURL() string {
	if u := os.Getenv("AVHSOL_GUARD_URL"); u != "" {
		return u
	}
	return "http://127.0.0.1:7077"
}

// RunChecks inspects the environment. Values of secrets are never read into the results: only whether they are set.
func RunChecks(ctx context.Context, root string) []Check {
	var out []Check
	add := func(c Check) { out = append(out, c) }
	if os.Getenv("AVHSOL_LLM_BASE_URL") != "" && os.Getenv("AVHSOL_LLM_MODEL") != "" {
		d := "endpoint and model set"
		if os.Getenv("AVHSOL_LLM_API_KEY") == "" {
			d += " (no API key set)"
		} else {
			d += ", key set"
		}
		add(Check{"Model", "ok", d, ""})
	} else {
		add(Check{"Model", "warn", "not configured: live runs are unavailable (the simulated model still works)", "export AVHSOL_LLM_BASE_URL, AVHSOL_LLM_MODEL and AVHSOL_LLM_API_KEY"})
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	if _, err := guard.New(GuardURL()).Metrics(cctx); err != nil {
		add(Check{"Guard proxy", "bad", "not reachable at " + GuardURL(), "start it: cd guard && cargo run --release -p avhsol-proxy (or ./scripts/demo.sh)"})
	} else {
		add(Check{"Guard proxy", "ok", "reachable at " + GuardURL(), ""})
	}
	cancel()
	if st, err := graph.Open(ctx, graph.LoadConfig()); err != nil {
		add(Check{"Neo4j graph", "off", "not reachable", "scripts/stack.sh up"})
	} else {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		if _, err := st.Stats(cctx); err != nil {
			add(Check{"Neo4j graph", "bad", "connected but a query failed", "scripts/stack.sh status"})
		} else {
			add(Check{"Neo4j graph", "ok", "connected", ""})
		}
		cancel()
		st.Close(ctx)
		ix := graph.LoadIndex()
		cctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		if err := ix.Q.Health(cctx); err != nil {
			add(Check{"Qdrant vectors", "bad", "not ready", "scripts/stack.sh status"})
		} else {
			add(Check{"Qdrant vectors", "ok", "ready", ""})
		}
		cancel()
	}
	sb := graph.Setting("AVHSOL_SANDBOX", "", home.Bin("avhsol-sandbox"))
	if _, err := os.Stat(sb); err != nil {
		add(Check{"Sandbox (Landlock)", "bad", "avhsol-sandbox not found", "cd guard && cargo build --release"})
	} else {
		add(Check{"Sandbox (Landlock)", "ok", "avhsol-sandbox present", ""})
	}
	if err := cliagent.GVisorAvailable(ctx); err != nil {
		add(Check{"Sandbox (gVisor)", "off", shortLine(err.Error()), "optional: install gVisor and run `runsc install`"})
	} else {
		add(Check{"Sandbox (gVisor)", "ok", "docker + runsc available", ""})
	}
	if export.PDFAvailable() {
		add(Check{"PDF reports", "ok", "Chrome or Chromium found", ""})
	} else {
		add(Check{"PDF reports", "warn", "no Chrome found", "install Chrome/Chromium or set AVHSOL_CHROME (html, md, json and sarif still work)"})
	}
	key := signingKey()
	if sg, err := sign.LoadSigner(key); err != nil {
		add(Check{"Trace signing", "warn", "no signing key: traces are hash-chained but not signed", "avhsol keygen"})
	} else if pub, err := sign.LoadPublic(key + ".pub"); err != nil {
		add(Check{"Trace signing", "warn", "key " + sg.ID + ", public key missing", "keep deploy/stack/signing.key.pub next to the private key"})
	} else if sign.KeyID(pub) != sg.ID {
		add(Check{"Trace signing", "bad", "the public key does not match the private key; signatures will not verify", "regenerate signing.key.pub from the private key"})
	} else {
		add(Check{"Trace signing", "ok", "key " + sg.ID + ", public key matches", ""})
	}
	if st, err := intel.Open(intel.Dir()); err == nil && st.Count() > 0 {
		add(Check{"Threat intel", "ok", fmt.Sprintf("%d records cached", st.Count()), ""})
	} else {
		add(Check{"Threat intel", "warn", "cache empty", "avhsol intel sync"})
	}
	return out
}

func shortLine(s string) string {
	if len(s) > 110 {
		return s[:109] + "…"
	}
	return s
}
