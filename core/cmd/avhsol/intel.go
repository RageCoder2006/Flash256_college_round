package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/41vi4p/avhsol/core/internal/api"
	"github.com/41vi4p/avhsol/core/internal/graph"
	"github.com/41vi4p/avhsol/core/internal/intel"
	"github.com/41vi4p/avhsol/core/internal/llm"
	"github.com/41vi4p/avhsol/core/internal/scenario"
	"github.com/41vi4p/avhsol/core/internal/sign"
)

func intelUsage() error {
	fmt.Fprintln(os.Stderr, `usage: avhsol intel <command>

  sync [-source ghsa,nvd,osv,feeds,kev,epss]   fetch threat intel into the local cache (the ONLY command that uses the network)
  status                                       what is cached and when each source last synced
  list [-q text] [-tag t] [-kev] [-n 20]       browse the cache, most urgent first
  show <id>                                    one item in full
  graph                                        load the cache into the Neo4j graph (Intel nodes) and vector store
  seeds -scenario S [-n 10] [-o seeds/intel-generated.yaml]   turn relevant intel into attack seeds (needs the model)
  export-bundle -o FILE                        write a signed bundle for an offline deployment
  import-bundle FILE [-allow-unsigned]         verify and load a bundle (no network used)

Tokens come from the environment only: AVHSOL_GITHUB_TOKEN, AVHSOL_NVD_API_KEY. Cache: $AVHSOL_INTEL_DIR (default deploy/stack/intel).`)
	return fmt.Errorf("missing or unknown intel command")
}

func cmdIntel(args []string) error {
	if len(args) == 0 {
		return intelUsage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch args[0] {
	case "sync":
		return intelSync(ctx, args[1:])
	case "status":
		return intelStatus()
	case "list":
		return intelList(args[1:])
	case "show":
		return intelShow(args[1:])
	case "seeds":
		return intelSeeds(ctx, args[1:])
	case "graph":
		return intelGraph(ctx)
	case "export-bundle":
		return intelExport(args[1:])
	case "import-bundle":
		return intelImport(args[1:])
	}
	return intelUsage()
}

func auditIntel(path, note string) {
	l, err := api.OpenAuditLog(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: audit log not written:", err)
		return
	}
	l.Write(api.AuditEntry{TS: time.Now().UnixMilli(), Who: "cli", Role: "operator", Remote: "local", Method: "CLI", Path: "intel", Status: 0, Note: note})
}

func intelSync(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("intel sync", flag.ExitOnError)
	src := fs.String("source", "", "comma-separated sources (default: all)")
	audit := fs.String("audit", "out/audit.jsonl", "audit log to record the sync in")
	_ = fs.Parse(args)
	sy, err := intel.Defaults(intel.Dir())
	if err != nil {
		return err
	}
	var names []string
	if *src != "" {
		names = strings.Split(*src, ",")
	}
	rep := sy.Run(ctx, names)
	if err := sy.Store.Save(); err != nil {
		return err
	}
	failed := 0
	for _, r := range rep.Results {
		line := fmt.Sprintf("  %-6s fetched %-4d new %-4d updated %-4d", r.Source, r.Fetched, r.Added, r.Updated)
		if r.Error != "" {
			failed++
			line += "  ERROR: " + r.Error
		}
		fmt.Println(line)
	}
	fmt.Printf("cache now holds %d items\n", rep.Total)
	b, _ := json.Marshal(rep.Results)
	auditIntel(*audit, "sync "+string(b))
	if failed == len(rep.Results) && failed > 0 {
		return fmt.Errorf("every source failed")
	}
	return nil
}

func openIntel() (*intel.Store, error) { return intel.Open(intel.Dir()) }

func intelStatus() error {
	st, err := openIntel()
	if err != nil {
		return err
	}
	fmt.Printf("%d items in %s\n", st.Count(), intel.Dir())
	for n, s := range st.State.Sources {
		fmt.Printf("  %-6s last sync %s  %s\n", n, orDash(s.LastSync), s.Error)
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

func intelList(args []string) error {
	fs := flag.NewFlagSet("intel list", flag.ExitOnError)
	q := fs.String("q", "", "text to search")
	tag := fs.String("tag", "", "tag, e.g. technique:tool_poisoning")
	kev := fs.Bool("kev", false, "only known-exploited")
	n := fs.Int("n", 20, "how many")
	_ = fs.Parse(args)
	st, err := openIntel()
	if err != nil {
		return err
	}
	for _, it := range st.Query(intel.Filter{Query: *q, Tag: *tag, KEV: *kev, Limit: *n}) {
		flags := ""
		if it.KEV {
			flags += " KEV"
		}
		if it.EPSS > 0 {
			flags += fmt.Sprintf(" EPSS %.2f", it.EPSS)
		}
		fmt.Printf("%-22s %-8s %-8s%s  %s\n", it.ID, it.Source, it.Severity, flags, it.Title)
	}
	return nil
}

func intelShow(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: avhsol intel show <id>")
	}
	st, err := openIntel()
	if err != nil {
		return err
	}
	it, ok := st.Get(args[0])
	if !ok {
		return fmt.Errorf("%s is not in the cache", args[0])
	}
	b, _ := json.MarshalIndent(it, "", "  ")
	fmt.Println(string(b))
	return nil
}

func intelSeeds(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("intel seeds", flag.ExitOnError)
	scPath := fs.String("scenario", "scenarios/devops-coder.yaml", "scenario the seeds are written for")
	n := fs.Int("n", 10, "how many intel items to use")
	out := fs.String("o", "seeds/intel-generated.yaml", "where to write the seeds")
	_ = fs.Parse(args)
	url, model := os.Getenv("AVHSOL_LLM_BASE_URL"), os.Getenv("AVHSOL_LLM_MODEL")
	if url == "" || model == "" {
		return fmt.Errorf("seed generation needs the model: set AVHSOL_LLM_BASE_URL and AVHSOL_LLM_MODEL")
	}
	sc, err := scenario.Load(*scPath)
	if err != nil {
		return err
	}
	st, err := openIntel()
	if err != nil {
		return err
	}
	tax, err := intel.LoadTaxonomy()
	if err != nil {
		return err
	}
	seeds, skipped, err := intel.GenerateSeeds(ctx, st, llm.New(url, model, os.Getenv("AVHSOL_LLM_API_KEY")), sc, tax, *n)
	for _, s := range skipped {
		fmt.Println("  skipped", s)
	}
	if err != nil {
		return err
	}
	if len(seeds) == 0 {
		return fmt.Errorf("no usable seeds (is the cache empty? run: avhsol intel sync)")
	}
	if err := os.WriteFile(*out, intel.SeedsYAML(seeds), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d seeds to %s (each carries the id of the advisory that inspired it)\n", len(seeds), *out)
	return nil
}

func intelExport(args []string) error {
	fs := flag.NewFlagSet("intel export-bundle", flag.ExitOnError)
	out := fs.String("o", "intel-bundle.json", "output file")
	_ = fs.Parse(args)
	st, err := openIntel()
	if err != nil {
		return err
	}
	signer, err := sign.LoadSigner(signingKeyPath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: no signing key; the bundle will be unsigned (run avhsol keygen)")
		signer = nil
	}
	b, err := intel.ExportBundle(st, signer, *out)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %d items to %s (sha256 %s, signed=%v)\n", len(b.Items), *out, b.SHA256[:12], b.Signature != "")
	return nil
}

func intelImport(args []string) error {
	fs := flag.NewFlagSet("intel import-bundle", flag.ExitOnError)
	unsigned := fs.Bool("allow-unsigned", false, "accept a bundle that cannot be verified")
	audit := fs.String("audit", "out/audit.jsonl", "audit log")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: avhsol intel import-bundle FILE")
	}
	st, err := openIntel()
	if err != nil {
		return err
	}
	pub, _ := sign.LoadPublic(signingKeyPath() + ".pub")
	added, updated, err := intel.ImportBundle(st, fs.Arg(0), pub, *unsigned)
	if err != nil {
		return err
	}
	if err := st.Save(); err != nil {
		return err
	}
	auditIntel(*audit, fmt.Sprintf("import-bundle %s added=%d updated=%d", fs.Arg(0), added, updated))
	fmt.Printf("imported: %d new, %d updated (cache holds %d)\n", added, updated, st.Count())
	return nil
}

func intelGraph(ctx context.Context) error {
	st, err := openIntel()
	if err != nil {
		return err
	}
	g, err := graph.Open(ctx, graph.LoadConfig())
	if err != nil {
		return err
	}
	defer g.Close(ctx)
	if err := g.EnsureSchema(ctx); err != nil {
		return err
	}
	n, err := g.IngestIntel(ctx, st.Query(intel.Filter{}), graph.LoadIndex())
	if err != nil {
		return err
	}
	fmt.Printf("%d intel items are now graph nodes linked to the techniques they motivate\n", n)
	return nil
}
