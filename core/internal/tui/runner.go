package tui

import (
	"bufio"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type lineMsg string
type doneMsg struct {
	err  error
	took time.Duration
}
type tickMsg time.Time

// proc is a running subprocess whose output is streamed into the interface.
type proc struct {
	cmd   *exec.Cmd
	ch    chan tea.Msg
	start time.Time
}

// startProc runs argv with stdout and stderr merged. The process gets its own process group, so cancelling stops the sandboxed
// agents it started too.
func startProc(argv []string) (*proc, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &proc{cmd: cmd, ch: make(chan tea.Msg, 256), start: time.Now()}
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 1<<20), 8<<20)
		for sc.Scan() {
			p.ch <- lineMsg(strings.TrimRight(sc.Text(), "\r"))
		}
	}()
	go func() {
		err := cmd.Wait()
		_ = pw.Close()
		time.Sleep(50 * time.Millisecond) // let the scanner drain
		p.ch <- doneMsg{err: err, took: time.Since(p.start)}
	}()
	return p, nil
}

// next waits for the process's next message.
func (p *proc) next() tea.Cmd {
	return func() tea.Msg { return <-p.ch }
}

// interrupt asks the run to stop (SIGINT to its group), and kills it if it has not after a few seconds.
func (p *proc) interrupt() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	pid := p.cmd.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGINT)
	go func() {
		time.Sleep(8 * time.Second)
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}()
}

func tick(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}
