package netmux

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
)

// Host and container joined by two pipes, as docker's stdin and stdout would be. On one machine the container side
// listens on 127.0.0.2 so it can use the same port number the host dials on 127.0.0.1.
func TestEndToEndTunnelsAllowedPortAndReportsOutput(t *testing.T) {
	svc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	port := svc.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := svc.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 64)
				n, _ := c.Read(b)
				_, _ = c.Write(append([]byte("echo:"), b[:n]...))
			}()
		}
	}()
	c2hR, c2hW := io.Pipe()
	h2cR, h2cW := io.Pipe()
	var agentOut bytes.Buffer
	hostDone := make(chan int, 1)
	go func() { code, _ := ServeHost(c2hR, h2cW, []int{port}, &agentOut); hostDone <- code }()
	script := `exec 3<>/dev/tcp/127.0.0.2/` + strconv.Itoa(port) + `; printf ping >&3; head -c 9 <&3; echo; exit 4`
	code, err := RunContainer(context.Background(), "127.0.0.2", []int{port}, []string{"bash", "-c", script}, h2cR, c2hW)
	if err != nil || code != 4 {
		t.Fatalf("container: code=%d err=%v", code, err)
	}
	if hc := <-hostDone; hc != 4 {
		t.Fatalf("host saw exit %d", hc)
	}
	if !strings.Contains(agentOut.String(), "echo:ping") {
		t.Fatalf("the tunnelled reply did not reach the agent; output %q", agentOut.String())
	}
}

func TestFramesRoundTrip(t *testing.T) {
	var b bytes.Buffer
	w := &writer{w: &b}
	_ = w.send(tData, 7, []byte("hello"))
	f, err := read(&b)
	if err != nil || f.t != tData || f.id != 7 || string(f.p) != "hello" {
		t.Fatalf("%v %+v", err, f)
	}
	if _, err := read(bytes.NewReader([]byte{tData, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff})); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestHostRefusesUnlistedPorts(t *testing.T) {
	secret, _ := net.Listen("tcp", "127.0.0.1:0")
	defer secret.Close()
	hit := make(chan struct{}, 1)
	go func() {
		if c, err := secret.Accept(); err == nil {
			hit <- struct{}{}
			c.Close()
		}
	}()
	secretPort := secret.Addr().(*net.TCPAddr).Port

	c2hR, c2hW := io.Pipe()
	h2cR, h2cW := io.Pipe()
	var out bytes.Buffer
	done := make(chan int, 1)
	go func() { code, _ := ServeHost(c2hR, h2cW, []int{1}, &out); done <- code }() // only port 1 allowed
	cw := &writer{w: c2hW}
	_ = cw.send(tOpen, 5, []byte(strconv.Itoa(secretPort)))
	f, err := read(h2cR) // the host must answer with a close, never connect
	if err != nil || f.t != tClose || f.id != 5 {
		t.Fatalf("want close for refused open, got %v %+v", err, f)
	}
	_ = cw.send(tOut, 0, []byte("agent says hi\n"))
	_ = cw.send(tExit, 0, []byte("3"))
	if code := <-done; code != 3 || out.String() != "agent says hi\n" {
		t.Fatalf("code=%d out=%q", code, out.String())
	}
	select {
	case <-hit:
		t.Fatal("host connected to a port that was not allowed")
	default:
	}
}
