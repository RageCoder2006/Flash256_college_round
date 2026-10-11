package sysmon

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Host is one sample of the machine.
type Host struct {
	At        int64      `json:"at_ms"`
	Supported bool       `json:"supported"`
	NCPU      int        `json:"ncpu"`
	Model     string     `json:"cpu_model,omitempty"`
	MHz       float64    `json:"cpu_mhz,omitempty"`
	CPU       float64    `json:"cpu_percent"`
	Cores     []float64  `json:"cores"`
	Load      [3]float64 `json:"load"`
	UptimeSec float64    `json:"uptime_sec"`
	Mem       Mem        `json:"mem"`
	PSI       PSI        `json:"psi"`
	Disks     []Disk     `json:"disks"`
	DiskRead  float64    `json:"disk_read_bps"`
	DiskWrite float64    `json:"disk_write_bps"`
	NetRx     float64    `json:"net_rx_bps"`
	NetTx     float64    `json:"net_tx_bps"`
	Temps     []Temp     `json:"temps,omitempty"`
}

type Disk struct {
	Path  string `json:"path"`
	Total uint64 `json:"total_bytes"`
	Used  uint64 `json:"used_bytes"`
	Free  uint64 `json:"free_bytes"`
}

type Temp struct {
	Label string  `json:"label"`
	C     float64 `json:"c"`
}

// Proc is one process (names only, never command lines: those can carry secrets).
type Proc struct {
	Component string  `json:"component"`
	Name      string  `json:"name"`
	PID       int     `json:"pid"`
	RSSBytes  uint64  `json:"rss_bytes"`
	CPU       float64 `json:"cpu_percent"` // of one core, like top
	Threads   int     `json:"threads"`
	FDs       int     `json:"fds"`
}

// Sandbox is the resource use of everything the current run started (Landlock-confined agent processes included).
type Sandbox struct {
	Active   bool    `json:"active"`
	RootPID  int     `json:"root_pid,omitempty"`
	Procs    int     `json:"processes"`
	RSSBytes uint64  `json:"rss_bytes"`
	CPU      float64 `json:"cpu_percent"`
	Threads  int     `json:"threads"`
	Top      []Proc  `json:"top,omitempty"`
	Limits   Limits  `json:"limits"`
}

// Limits are the configured ceilings, shown beside the usage. Zero means "not limited", and the UI says so.
type Limits struct {
	Isolation   string `json:"isolation"`
	MaxProcs    int    `json:"max_procs"`
	MemoryBytes uint64 `json:"memory_bytes"` // 0 = unlimited
	CPUSeconds  int    `json:"cpu_seconds"`
	Note        string `json:"note,omitempty"`
}

// Container is one docker container (gVisor episodes, the Neo4j/Qdrant stack).
type Container struct {
	Name     string  `json:"name"`
	CPU      float64 `json:"cpu_percent"`
	MemBytes float64 `json:"mem_bytes"`
	MemLimit float64 `json:"mem_limit_bytes"`
	MemPct   float64 `json:"mem_percent"`
	PIDs     int     `json:"pids"`
	NetIO    string  `json:"net_io,omitempty"`
	Kind     string  `json:"kind"` // episode | stack
}

// Snapshot is everything the Status page shows.
type Snapshot struct {
	Host       Host        `json:"host"`
	Procs      []Proc      `json:"procs"`
	Sandbox    Sandbox     `json:"sandbox"`
	Containers []Container `json:"containers"`
}

// Config tells the sampler what to watch. Callbacks keep sysmon free of API types.
type Config struct {
	Interval time.Duration
	History  int           // samples kept (default 900)
	Paths    []string      // directories whose disk usage is reported (runs directory, ...)
	RunPID   func() int    // pid of the current run's root process, 0 if none
	Limits   func() Limits // configured sandbox limits
	Proc     string        // override for tests: root of a /proc-like tree
}

type Sampler struct {
	cfg     Config
	mu      sync.Mutex
	hist    []Snapshot
	prevCPU map[string]cpuTicks
	prevNet map[string]netCounters
	prevDsk map[string]diskCounters
	prevAt  time.Time
	prevPID map[int]uint64
	dock    []Container
	stop    chan struct{}
}

func New(cfg Config) *Sampler {
	if cfg.Interval <= 0 {
		cfg.Interval = 2 * time.Second
	}
	if cfg.History <= 0 {
		cfg.History = 900
	}
	if cfg.Proc == "" {
		cfg.Proc = "/proc"
	}
	return &Sampler{cfg: cfg, prevPID: map[int]uint64{}, stop: make(chan struct{})}
}

// Supported reports whether this platform exposes /proc.
func Supported() bool { return runtime.GOOS == "linux" }

// Start samples until Stop. The first sample has no rates (they need two readings), so it is taken immediately and again soon after.
func (s *Sampler) Start() {
	go s.refreshContainers()
	go func() {
		s.Sample()
		t := time.NewTicker(s.cfg.Interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.Sample()
			case <-s.stop:
				return
			}
		}
	}()
}

func (s *Sampler) Stop() { close(s.stop) }

// Latest returns the newest snapshot.
func (s *Sampler) Latest() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hist) == 0 {
		return Snapshot{Host: Host{Supported: Supported()}}
	}
	return s.hist[len(s.hist)-1]
}

// History returns the last n seconds of snapshots, oldest first.
func (s *Sampler) History(seconds int) []Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := int(time.Duration(seconds)*time.Second/s.cfg.Interval) + 1
	if n <= 0 || n > len(s.hist) {
		n = len(s.hist)
	}
	return append([]Snapshot(nil), s.hist[len(s.hist)-n:]...)
}

func (s *Sampler) read(name string) string {
	b, _ := os.ReadFile(filepath.Join(s.cfg.Proc, name))
	return string(b)
}

// Sample takes one reading and appends it to the history.
func (s *Sampler) Sample() Snapshot {
	now := time.Now()
	snap := Snapshot{Host: Host{At: now.UnixMilli(), Supported: Supported(), NCPU: runtime.NumCPU()}}
	if !Supported() && s.cfg.Proc == "/proc" {
		s.push(snap)
		return snap
	}
	dt := now.Sub(s.prevAt).Seconds()
	h := &snap.Host
	cur := parseStat(s.read("stat"))
	if s.prevCPU != nil {
		h.CPU = pct(s.prevCPU["cpu"], cur["cpu"])
	}
	var names []string
	for k := range cur {
		if k != "cpu" {
			names = append(names, k)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		a, _ := strconv.Atoi(names[i][3:])
		b, _ := strconv.Atoi(names[j][3:])
		return a < b
	})
	for _, n := range names {
		v := 0.0
		if s.prevCPU != nil {
			v = pct(s.prevCPU[n], cur[n])
		}
		h.Cores = append(h.Cores, v)
	}
	if len(names) > 0 {
		h.NCPU = len(names)
	}
	s.prevCPU = cur
	h.Mem = parseMeminfo(s.read("meminfo"))
	h.Load = parseLoadavg(s.read("loadavg"))
	h.UptimeSec = parseUptime(s.read("uptime"))
	if v, ok := parsePSI(s.read("pressure/cpu")); ok {
		h.PSI.CPU, h.PSI.OK = v, true
	}
	h.PSI.Mem, _ = parsePSI(s.read("pressure/memory"))
	h.PSI.IO, _ = parsePSI(s.read("pressure/io"))
	h.Model, h.MHz = cpuInfo(s.read("cpuinfo"))
	net := parseNetDev(s.read("net/dev"))
	dsk := parseDiskstats(s.read("diskstats"))
	if s.prevNet != nil && dt > 0 {
		var rx, tx uint64
		for k, c := range net {
			p := s.prevNet[k]
			if c.rx >= p.rx {
				rx += c.rx - p.rx
			}
			if c.tx >= p.tx {
				tx += c.tx - p.tx
			}
		}
		h.NetRx, h.NetTx = float64(rx)/dt, float64(tx)/dt
		var r, w uint64
		for k, c := range dsk {
			p := s.prevDsk[k]
			if c.readSectors >= p.readSectors {
				r += c.readSectors - p.readSectors
			}
			if c.writeSectors >= p.writeSectors {
				w += c.writeSectors - p.writeSectors
			}
		}
		h.DiskRead, h.DiskWrite = float64(r)*512/dt, float64(w)*512/dt
	}
	s.prevNet, s.prevDsk, s.prevAt = net, dsk, now
	seen := map[string]bool{}
	for _, p := range append([]string{"/"}, s.cfg.Paths...) {
		if abs, err := filepath.Abs(p); err == nil && !seen[abs] {
			seen[abs] = true
			var st syscall.Statfs_t
			if syscall.Statfs(abs, &st) == nil {
				total := st.Blocks * uint64(st.Bsize)
				free := st.Bavail * uint64(st.Bsize)
				h.Disks = append(h.Disks, Disk{Path: abs, Total: total, Free: free, Used: total - st.Bfree*uint64(st.Bsize)})
			}
		}
	}
	h.Temps = temperatures()
	s.processes(&snap, dt)
	s.mu.Lock()
	snap.Containers = s.dock
	s.mu.Unlock()
	s.push(snap)
	return snap
}

func (s *Sampler) push(snap Snapshot) {
	s.mu.Lock()
	s.hist = append(s.hist, snap)
	if len(s.hist) > s.cfg.History {
		s.hist = s.hist[len(s.hist)-s.cfg.History:]
	}
	s.mu.Unlock()
}

func cpuInfo(s string) (string, float64) {
	var model string
	var mhz float64
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "model name":
			if model == "" {
				model = strings.TrimSpace(v)
			}
		case "cpu MHz":
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && f > mhz {
				mhz = f
			}
		}
	}
	return model, mhz
}

func temperatures() []Temp {
	var out []Temp
	zones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	for _, z := range zones {
		b, err := os.ReadFile(z)
		if err != nil {
			continue
		}
		v, _ := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
		label := "zone"
		if t, err := os.ReadFile(filepath.Join(filepath.Dir(z), "type")); err == nil {
			label = strings.TrimSpace(string(t))
		}
		out = append(out, Temp{Label: label, C: v / 1000})
	}
	if len(out) == 0 {
		hw, _ := filepath.Glob("/sys/class/hwmon/hwmon*/temp1_input")
		for _, z := range hw {
			if b, err := os.ReadFile(z); err == nil {
				v, _ := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
				name := "hwmon"
				if t, err := os.ReadFile(filepath.Join(filepath.Dir(z), "name")); err == nil {
					name = strings.TrimSpace(string(t))
				}
				out = append(out, Temp{Label: name, C: v / 1000})
			}
		}
	}
	return out
}

type procInfo struct {
	pid int
	st  procStat
}

// processes fills the component list and the run's sandbox usage. CPU% needs two readings of a process, so the first one reads 0.
func (s *Sampler) processes(snap *Snapshot, dt float64) {
	root := s.cfg.Proc
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	all := map[int]procInfo{}
	children := map[int][]int{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, e.Name(), "stat"))
		if err != nil {
			continue
		}
		st, err := parseProcStat(string(b))
		if err != nil {
			continue
		}
		all[pid] = procInfo{pid, st}
		children[st.PPID] = append(children[st.PPID], pid)
	}
	page := uint64(os.Getpagesize())
	hz := 100.0 // USER_HZ is 100 on every Linux we run on
	mk := func(component string, pi procInfo) Proc {
		p := Proc{Component: component, Name: pi.st.Comm, PID: pi.pid, Threads: pi.st.Threads}
		if pi.st.RSSPgs > 0 {
			p.RSSBytes = uint64(pi.st.RSSPgs) * page
		}
		if prev, ok := s.prevPID[pi.pid]; ok && dt > 0 && pi.st.Ticks >= prev {
			p.CPU = float64(pi.st.Ticks-prev) / hz / dt * 100
		}
		if fds, err := os.ReadDir(filepath.Join(root, strconv.Itoa(pi.pid), "fd")); err == nil {
			p.FDs = len(fds)
		}
		return p
	}
	next := map[int]uint64{}
	for pid, pi := range all {
		next[pid] = pi.st.Ticks
	}
	self := os.Getpid()
	if pi, ok := all[self]; ok {
		snap.Procs = append(snap.Procs, mk("api", pi))
	}
	for _, pi := range all {
		switch pi.st.Comm {
		case "avhsol-proxy":
			snap.Procs = append(snap.Procs, mk("guard proxy", pi))
		case "next-server (v1", "next-server":
			snap.Procs = append(snap.Procs, mk("dashboard", pi))
		}
	}
	sort.Slice(snap.Procs, func(i, j int) bool { return snap.Procs[i].Component < snap.Procs[j].Component })
	sb := Sandbox{}
	if s.cfg.Limits != nil {
		sb.Limits = s.cfg.Limits()
	}
	if s.cfg.RunPID != nil {
		if rp := s.cfg.RunPID(); rp > 0 {
			if _, ok := all[rp]; ok {
				sb.Active, sb.RootPID = true, rp
				var members []Proc
				stack := []int{rp}
				for len(stack) > 0 {
					p := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					if pi, ok := all[p]; ok {
						pr := mk("run", pi)
						members = append(members, pr)
						sb.RSSBytes += pr.RSSBytes
						sb.CPU += pr.CPU
						sb.Threads += pr.Threads
					}
					stack = append(stack, children[p]...)
				}
				sb.Procs = len(members)
				sort.Slice(members, func(i, j int) bool { return members[i].RSSBytes > members[j].RSSBytes })
				if len(members) > 8 {
					members = members[:8]
				}
				sb.Top = members
			}
		}
	}
	snap.Sandbox = sb
	s.prevPID = next
}

// refreshContainers reads `docker stats` (slow: seconds) in its own goroutine every 5 s, so a sample never waits for it.
func (s *Sampler) refreshContainers() {
	if _, err := exec.LookPath("docker"); err != nil {
		return
	}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		var out bytes.Buffer
		cmd := exec.CommandContext(ctx, "docker", "stats", "--no-stream", "--format", "{{json .}}")
		cmd.Stdout = &out
		var cs []Container
		if cmd.Run() == nil {
			cs = parseDockerStats(out.String())
		}
		cancel()
		s.mu.Lock()
		s.dock = cs
		s.mu.Unlock()
		select {
		case <-time.After(5 * time.Second):
		case <-s.stop:
			return
		}
	}
}

func parseDockerStats(s string) []Container {
	var cs []Container
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if line == "" {
			continue
		}
		var r struct{ Name, CPUPerc, MemUsage, MemPerc, NetIO, PIDs string }
		if json.Unmarshal([]byte(line), &r) != nil || !strings.HasPrefix(r.Name, "avhsol-") {
			continue
		}
		used, limit, _ := strings.Cut(r.MemUsage, "/")
		pids, _ := strconv.Atoi(strings.TrimSpace(r.PIDs))
		kind := "stack"
		if strings.HasPrefix(r.Name, "avhsol-ep-") {
			kind = "episode"
		}
		cs = append(cs, Container{Name: r.Name, CPU: parseDockerPercent(r.CPUPerc), MemBytes: parseSize(used), MemLimit: parseSize(limit),
			MemPct: parseDockerPercent(r.MemPerc), PIDs: pids, NetIO: r.NetIO, Kind: kind})
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
	return cs
}
