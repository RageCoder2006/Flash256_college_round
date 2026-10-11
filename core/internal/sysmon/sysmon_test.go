package sysmon

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func near(a, b float64) bool { return math.Abs(a-b) < 0.05 }

func TestCPUPercentFromTickDeltas(t *testing.T) {
	a := parseStat("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0\ncpu1 50 0 50 400 0 0 0 0 0 0\nintr 1\n")
	b := parseStat("cpu  200 0 200 1000 0 0 0 0 0 0\ncpu0 150 0 50 400 0 0 0 0 0 0\ncpu1 50 0 150 600 0 0 0 0 0 0\n")
	if got := pct(a["cpu"], b["cpu"]); !near(got, 50) {
		t.Fatalf("total %v", got)
	}
	if got := pct(a["cpu0"], b["cpu0"]); !near(got, 100) {
		t.Fatalf("busy core %v", got)
	}
	if got := pct(a["cpu1"], b["cpu1"]); !near(got, 33.3) {
		t.Fatalf("one-third core %v", got)
	}
	if pct(a["cpu"], a["cpu"]) != 0 {
		t.Fatal("no time elapsed must read 0, not NaN")
	}
}

func TestMeminfoSwapAndAvailable(t *testing.T) {
	m := parseMeminfo("MemTotal: 16000000 kB\nMemFree: 2000000 kB\nMemAvailable: 9000000 kB\nBuffers: 100000 kB\nCached: 5000000 kB\nDirty: 1234 kB\nSwapTotal: 8000000 kB\nSwapFree: 7500000 kB\n")
	if m.UsedKB != 7000000 || m.SwapUsedKB != 500000 || m.CachedKB != 5000000 || m.DirtyKB != 1234 {
		t.Fatalf("%+v", m)
	}
	if parseMeminfo("MemTotal: 100 kB\nMemFree: 10 kB\nCached: 20 kB\nBuffers: 5 kB\n").AvailableKB != 35 {
		t.Fatal("fallback for kernels without MemAvailable")
	}
}

func TestLoadUptimePSI(t *testing.T) {
	if l := parseLoadavg("1.50 0.75 0.25 2/500 12345\n"); l != [3]float64{1.5, 0.75, 0.25} {
		t.Fatal(l)
	}
	if parseUptime("1234.56 5678.9\n") != 1234.56 {
		t.Fatal("uptime")
	}
	v, ok := parsePSI("some avg10=3.25 avg60=1.00 avg300=0.50 total=12345\nfull avg10=1.00 avg60=0 avg300=0 total=1\n")
	if !ok || v != 3.25 {
		t.Fatal(v, ok)
	}
	if _, ok := parsePSI(""); ok {
		t.Fatal("missing file must not read as 0%")
	}
}

func TestNetAndDiskCountersIgnoreLoopbackAndPartitions(t *testing.T) {
	n := parseNetDev("Inter-|   Receive\n face |bytes\n    lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n  eth0: 1000 5 0 0 0 0 0 0 2000 6 0 0 0 0 0 0\n")
	if len(n) != 1 || n["eth0"].rx != 1000 || n["eth0"].tx != 2000 {
		t.Fatalf("%v", n)
	}
	d := parseDiskstats("   8  0 sda 1 0 100 0 1 0 200 0 0 0 0\n   8  1 sda1 1 0 50 0 1 0 60 0 0 0 0\n 259 0 nvme0n1 1 0 300 0 1 0 400 0 0 0 0\n 259 1 nvme0n1p1 1 0 5 0 1 0 6 0 0 0 0\n   7  0 loop0 1 0 9 0 1 0 9 0 0 0 0\n")
	if len(d) != 2 || d["sda"].readSectors != 100 || d["nvme0n1"].writeSectors != 400 {
		t.Fatalf("%v", d)
	}
}

func TestProcStatWithAwkwardNames(t *testing.T) {
	// a command name containing spaces and parentheses must not shift the fields
	line := "4242 (weird (name) x) S 100 4242 4242 0 -1 4194304 1000 0 0 0 150 50 0 0 20 0 7 0 12345 1000000 321 18446744073709551615"
	p, err := parseProcStat(line)
	if err != nil || p.Comm != "weird (name) x" || p.PPID != 100 || p.Ticks != 200 || p.Threads != 7 || p.RSSPgs != 321 {
		t.Fatalf("%v %+v", err, p)
	}
	if _, err := parseProcStat("garbage"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestDockerStatsParsing(t *testing.T) {
	cs := parseDockerStats(`{"Name":"avhsol-ep-abc","CPUPerc":"12.50%","MemUsage":"100MiB / 2GiB","MemPerc":"4.88%","NetIO":"0B / 0B","PIDs":"9"}
{"Name":"someone-elses","CPUPerc":"1%","MemUsage":"1MiB / 2GiB","MemPerc":"0%","NetIO":"","PIDs":"1"}
{"Name":"avhsol-stack-neo4j-1","CPUPerc":"1.00%","MemUsage":"1.2GiB / 7.5GiB","MemPerc":"16%","NetIO":"1kB / 2kB","PIDs":"60"}`)
	if len(cs) != 2 || cs[0].Kind != "episode" || cs[0].CPU != 12.5 || cs[0].MemBytes != 100<<20 || cs[0].MemLimit != 2<<30 || cs[0].PIDs != 9 || cs[1].Kind != "stack" {
		t.Fatalf("%+v", cs)
	}
}

func fakeProc(t *testing.T) string {
	root := t.TempDir()
	write := func(rel, s string) {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("stat", "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 100 0 100 800 0 0 0 0 0 0\n")
	write("meminfo", "MemTotal: 1000 kB\nMemAvailable: 400 kB\nSwapTotal: 100 kB\nSwapFree: 40 kB\n")
	write("loadavg", "0.5 0.4 0.3 1/2 3\n")
	write("uptime", "100.0 1.0\n")
	write("net/dev", "h\nh\n eth0: 0 0 0 0 0 0 0 0 0 0\n")
	write("diskstats", "")
	// a run tree: 10 (run root) -> 11 -> 12
	for pid, ppid := range map[int]int{10: 1, 11: 10, 12: 11, 99: 1} {
		write(filepath.Join(itoa(pid), "stat"), itoa(pid)+" (p"+itoa(pid)+") S "+itoa(ppid)+" 0 0 0 -1 0 0 0 0 0 10 10 0 0 20 0 2 0 1 1 100 0")
		_ = os.MkdirAll(filepath.Join(root, itoa(pid), "fd"), 0o755)
	}
	return root
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestSandboxAccountingWalksTheRunSubtreeOnly(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	s := New(Config{Proc: fakeProc(t), RunPID: func() int { return 10 }, Limits: func() Limits { return Limits{Isolation: "landlock", MaxProcs: 512} }})
	snap := s.Sample()
	if !snap.Sandbox.Active || snap.Sandbox.Procs != 3 || snap.Sandbox.Threads != 6 {
		t.Fatalf("subtree wrong: %+v", snap.Sandbox)
	}
	if snap.Sandbox.Limits.MaxProcs != 512 || snap.Sandbox.Limits.MemoryBytes != 0 {
		t.Fatal("limits must pass through, unlimited memory stays 0")
	}
	if snap.Host.Mem.SwapUsedKB != 60 || snap.Host.Mem.UsedKB != 600 {
		t.Fatalf("%+v", snap.Host.Mem)
	}
	time.Sleep(10 * time.Millisecond)
	snap = s.Sample()
	if len(s.History(60)) != 2 || snap.Host.Cores == nil {
		t.Fatal("history or cores missing")
	}
	none := New(Config{Proc: fakeProc(t), RunPID: func() int { return 0 }})
	if none.Sample().Sandbox.Active {
		t.Fatal("no run, no sandbox usage")
	}
}

func TestLiveSampleOnThisMachine(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	s := New(Config{})
	s.Sample()
	time.Sleep(300 * time.Millisecond)
	h := s.Sample().Host
	if !h.Supported || h.Mem.TotalKB == 0 || h.UptimeSec <= 0 || len(h.Cores) == 0 || len(h.Disks) == 0 {
		t.Fatalf("a live read of /proc looks empty: %+v", h)
	}
	if h.CPU < 0 || h.CPU > 100 {
		t.Fatal(h.CPU)
	}
}
