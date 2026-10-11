// Package sysmon reads the state of the machine the tests run on (CPU, memory, swap, load, disk, network, pressure,
// temperatures) and of the processes and containers AVHSOL starts. It reads /proc and /sys directly, needs no root, and
// is Linux only: elsewhere it reports that it is unsupported rather than guessing. Parsers take plain text so they are
// tested against fixtures.
package sysmon

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// cpuTicks are the cumulative jiffies of one CPU line in /proc/stat.
type cpuTicks struct{ busy, total uint64 }

// parseStat returns the aggregate line first (key "cpu") and then each core ("cpu0", ...).
func parseStat(s string) map[string]cpuTicks {
	out := map[string]cpuTicks{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		var v [10]uint64
		for i := 1; i < len(f) && i <= 10; i++ {
			v[i-1], _ = strconv.ParseUint(f[i], 10, 64)
		}
		idle := v[3] + v[4] // idle + iowait
		var total uint64
		for _, x := range v[:8] { // user nice system idle iowait irq softirq steal (guest is already inside user)
			total += x
		}
		out[f[0]] = cpuTicks{busy: total - idle, total: total}
	}
	return out
}

func pct(prev, cur cpuTicks) float64 {
	dt := float64(cur.total) - float64(prev.total)
	if dt <= 0 {
		return 0
	}
	p := 100 * (float64(cur.busy) - float64(prev.busy)) / dt
	if p < 0 {
		return 0
	}
	if p > 100 {
		return 100
	}
	return p
}

// Mem is memory in kibibytes, as /proc/meminfo reports it.
type Mem struct {
	TotalKB     uint64 `json:"total_kb"`
	AvailableKB uint64 `json:"available_kb"`
	UsedKB      uint64 `json:"used_kb"` // total - available
	CachedKB    uint64 `json:"cached_kb"`
	BuffersKB   uint64 `json:"buffers_kb"`
	FreeKB      uint64 `json:"free_kb"`
	DirtyKB     uint64 `json:"dirty_kb"`
	SwapTotalKB uint64 `json:"swap_total_kb"`
	SwapUsedKB  uint64 `json:"swap_used_kb"`
}

func parseMeminfo(s string) Mem {
	kv := map[string]uint64{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		k, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, _ := strconv.ParseUint(f[0], 10, 64)
		kv[k] = v
	}
	m := Mem{TotalKB: kv["MemTotal"], AvailableKB: kv["MemAvailable"], CachedKB: kv["Cached"], BuffersKB: kv["Buffers"], FreeKB: kv["MemFree"],
		DirtyKB: kv["Dirty"], SwapTotalKB: kv["SwapTotal"]}
	if _, ok := kv["MemAvailable"]; !ok { // very old kernels
		m.AvailableKB = kv["MemFree"] + kv["Cached"] + kv["Buffers"]
	}
	if m.TotalKB > m.AvailableKB {
		m.UsedKB = m.TotalKB - m.AvailableKB
	}
	if kv["SwapTotal"] > kv["SwapFree"] {
		m.SwapUsedKB = kv["SwapTotal"] - kv["SwapFree"]
	}
	return m
}

func parseLoadavg(s string) [3]float64 {
	var l [3]float64
	f := strings.Fields(s)
	for i := 0; i < 3 && i < len(f); i++ {
		l[i], _ = strconv.ParseFloat(f[i], 64)
	}
	return l
}

func parseUptime(s string) float64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

// PSI is the "some" avg10 stall percentage for each resource: how much of the last 10 s tasks waited for it.
type PSI struct {
	CPU float64 `json:"cpu"`
	Mem float64 `json:"mem"`
	IO  float64 `json:"io"`
	OK  bool    `json:"ok"` // false when the kernel does not provide pressure files
}

func parsePSI(s string) (float64, bool) {
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, tok := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(tok, "avg10="); ok {
				f, err := strconv.ParseFloat(v, 64)
				return f, err == nil
			}
		}
	}
	return 0, false
}

type netCounters struct{ rx, tx uint64 }

// parseNetDev sums every interface except loopback and virtual container bridges' veth noise is kept (it is real traffic).
func parseNetDev(s string) map[string]netCounters {
	out := map[string]netCounters{}
	for _, line := range strings.Split(s, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if len(f) < 9 || name == "lo" {
			continue
		}
		rx, _ := strconv.ParseUint(f[0], 10, 64)
		tx, _ := strconv.ParseUint(f[8], 10, 64)
		out[name] = netCounters{rx, tx}
	}
	return out
}

type diskCounters struct{ readSectors, writeSectors uint64 }

// parseDiskstats keeps whole disks only (sda, nvme0n1, vda), not partitions or loop/ram devices, so the totals do not double count.
func parseDiskstats(s string) map[string]diskCounters {
	out := map[string]diskCounters{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		name := f[2]
		if !wholeDisk(name) {
			continue
		}
		r, _ := strconv.ParseUint(f[5], 10, 64)
		w, _ := strconv.ParseUint(f[9], 10, 64)
		out[name] = diskCounters{r, w}
	}
	return out
}

func wholeDisk(n string) bool {
	switch {
	case strings.HasPrefix(n, "loop"), strings.HasPrefix(n, "ram"), strings.HasPrefix(n, "dm-"), strings.HasPrefix(n, "zram"), strings.HasPrefix(n, "sr"):
		return false
	case strings.HasPrefix(n, "nvme"), strings.HasPrefix(n, "mmcblk"):
		return !strings.Contains(n[strings.IndexAny(n, "0123456789"):], "p") // nvme0n1 yes, nvme0n1p2 no
	case strings.HasPrefix(n, "sd"), strings.HasPrefix(n, "vd"), strings.HasPrefix(n, "xvd"), strings.HasPrefix(n, "hd"):
		return !strings.ContainsAny(n[len(n)-1:], "0123456789")
	}
	return false
}

// procStat is the part of /proc/<pid>/stat we use. The command name is in parentheses and may itself contain spaces
// and parentheses, so the fields after it are found from the LAST closing parenthesis.
type procStat struct {
	Comm    string
	PPID    int
	Ticks   uint64 // utime + stime
	Threads int
	RSSPgs  int64
}

func parseProcStat(s string) (procStat, error) {
	i, j := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if i < 0 || j < i {
		return procStat{}, fmt.Errorf("malformed stat")
	}
	p := procStat{Comm: s[i+1 : j]}
	f := strings.Fields(s[j+1:])
	// f[0]=state f[1]=ppid ... f[11]=utime f[12]=stime ... f[17]=num_threads ... f[21]=rss
	if len(f) < 22 {
		return p, fmt.Errorf("short stat")
	}
	p.PPID, _ = strconv.Atoi(f[1])
	ut, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	p.Ticks = ut + st
	p.Threads, _ = strconv.Atoi(f[17])
	p.RSSPgs, _ = strconv.ParseInt(f[21], 10, 64)
	return p, nil
}

// parseDockerPercent turns "12.50%" into 12.5.
func parseDockerPercent(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(s), "%"), 64)
	return v
}

// parseSize turns "12.5MiB", "1.2GiB", "300kB" into bytes.
func parseSize(s string) float64 {
	s = strings.TrimSpace(s)
	units := []struct {
		suf string
		mul float64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"kB", 1e3}, {"KB", 1e3}, {"B", 1}}
	for _, u := range units {
		if v, ok := strings.CutSuffix(s, u.suf); ok {
			f, _ := strconv.ParseFloat(strings.TrimSpace(v), 64)
			return f * u.mul
		}
	}
	return 0
}
