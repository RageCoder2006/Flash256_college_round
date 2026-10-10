// Package netmux tunnels a few TCP ports between the host and a container that has NO network, over the
// container's stdin/stdout. It exists so the gVisor backend can give an agent exactly the ports it is allowed
// (the guard proxy, the canary sink) and nothing else, without iptables or a bridge.
//
// Wire format: 1 byte type, 4 bytes connection id, 4 bytes payload length (big endian), payload.
package netmux

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"sync"
)

const (
	tOpen  = 'O' // container -> host: open a connection to port (payload = decimal port)
	tData  = 'D' // either way: bytes of a connection
	tClose = 'C' // either way: a connection ended
	tOut   = 'S' // container -> host: output of the agent command
	tExit  = 'X' // container -> host: the agent command ended (payload = decimal exit code)

	maxPayload = 1 << 20
)

type frame struct {
	t  byte
	id uint32
	p  []byte
}

type writer struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *writer) send(t byte, id uint32, p []byte) error {
	var h [9]byte
	h[0] = t
	binary.BigEndian.PutUint32(h[1:5], id)
	binary.BigEndian.PutUint32(h[5:9], uint32(len(p)))
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.w.Write(h[:]); err != nil {
		return err
	}
	if len(p) == 0 {
		return nil
	}
	_, err := w.w.Write(p)
	return err
}

func read(r io.Reader) (frame, error) {
	var h [9]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return frame{}, err
	}
	n := binary.BigEndian.Uint32(h[5:9])
	if n > maxPayload {
		return frame{}, fmt.Errorf("netmux: frame of %d bytes", n)
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return frame{}, err
	}
	return frame{h[0], binary.BigEndian.Uint32(h[1:5]), p}, nil
}

type conns struct {
	mu sync.Mutex
	m  map[uint32]net.Conn
}

func (c *conns) put(id uint32, nc net.Conn) { c.mu.Lock(); c.m[id] = nc; c.mu.Unlock() }
func (c *conns) get(id uint32) net.Conn     { c.mu.Lock(); defer c.mu.Unlock(); return c.m[id] }
func (c *conns) drop(id uint32) net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	nc := c.m[id]
	delete(c.m, id)
	return nc
}
func (c *conns) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, nc := range c.m {
		_ = nc.Close()
	}
}

func pump(nc net.Conn, w *writer, id uint32) {
	buf := make([]byte, 32<<10)
	for {
		n, err := nc.Read(buf)
		if n > 0 {
			if w.send(tData, id, buf[:n]) != nil {
				return
			}
		}
		if err != nil {
			_ = w.send(tClose, id, nil)
			return
		}
	}
}

// ServeHost runs on the host. r and w are the container's stdout and stdin. Only ports in allowed are dialled, on
// 127.0.0.1; anything else is refused. The agent's output is written to out. It returns the agent's exit code.
func ServeHost(r io.Reader, w io.Writer, allowed []int, out io.Writer) (int, error) {
	ok := map[int]bool{}
	for _, p := range allowed {
		ok[p] = true
	}
	wr := &writer{w: w}
	cs := &conns{m: map[uint32]net.Conn{}}
	defer cs.closeAll()
	for {
		f, err := read(r)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return -1, io.EOF
			}
			return -1, err
		}
		switch f.t {
		case tOpen:
			port, _ := strconv.Atoi(string(f.p))
			if !ok[port] {
				_ = wr.send(tClose, f.id, nil)
				continue
			}
			nc, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				_ = wr.send(tClose, f.id, nil)
				continue
			}
			cs.put(f.id, nc)
			go pump(nc, wr, f.id)
		case tData:
			if nc := cs.get(f.id); nc != nil {
				_, _ = nc.Write(f.p)
			}
		case tClose:
			if nc := cs.drop(f.id); nc != nil {
				_ = nc.Close()
			}
		case tOut:
			_, _ = out.Write(f.p)
		case tExit:
			code, _ := strconv.Atoi(string(f.p))
			return code, nil
		}
	}
}

// RunContainer runs inside the container. It listens on 127.0.0.1 for each port, relays accepted connections to the
// host over out (bind is the address it listens on: 127.0.0.1 in a container), runs argv, and reports its output and exit code. in/out are the container's stdin/stdout.
func RunContainer(ctx context.Context, bind string, ports []int, argv []string, in io.Reader, out io.Writer) (int, error) {
	if bind == "" {
		bind = "127.0.0.1"
	}
	if len(argv) == 0 {
		return 2, fmt.Errorf("no command")
	}
	wr := &writer{w: out}
	cs := &conns{m: map[uint32]net.Conn{}}
	defer cs.closeAll()
	var nextID uint32
	var idMu sync.Mutex
	for _, p := range ports {
		ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(p)))
		if err != nil {
			return 2, err
		}
		defer ln.Close()
		go func(ln net.Listener, port int) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				idMu.Lock()
				nextID++
				id := nextID
				idMu.Unlock()
				cs.put(id, c)
				if wr.send(tOpen, id, []byte(strconv.Itoa(port))) != nil {
					return
				}
				go pump(c, wr, id)
			}
		}(ln, p)
	}
	go func() { // host -> container frames
		for {
			f, err := read(in)
			if err != nil {
				return
			}
			switch f.t {
			case tData:
				if c := cs.get(f.id); c != nil {
					_, _ = c.Write(f.p)
				}
			case tClose:
				if c := cs.drop(f.id); c != nil {
					_ = c.Close()
				}
			}
		}
	}()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	var pumped sync.WaitGroup
	pumped.Add(1)
	go func() {
		defer pumped.Done()
		buf := make([]byte, 16<<10)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				_ = wr.send(tOut, 0, buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = 127
			_ = wr.send(tOut, 0, []byte(err.Error()+"\n"))
		}
	}
	_ = pw.Close()
	pumped.Wait()
	_ = wr.send(tExit, 0, []byte(strconv.Itoa(code)))
	return code, nil
}
