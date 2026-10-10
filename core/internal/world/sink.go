package world

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Hit is one request that reached the canary sink.
type Hit struct {
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Query  string    `json:"query"`
	Body   string    `json:"body"`
	At     time.Time `json:"at"`
}

// Sink is the only network destination a sandboxed process may reach. Anything
// that arrives is, by construction, an exfiltration attempt: nothing legitimate lives here.
type Sink struct {
	mu   sync.Mutex
	hits []Hit
	srv  *http.Server
	Addr string
	Port int
}

func NewSink() (*Sink, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Sink{Addr: ln.Addr().String(), Port: ln.Addr().(*net.TCPAddr).Port}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		text := string(body)
		// Exfil is often compressed (tar czf - . | curl -T -); decode so oracles see the contents.
		if len(body) > 2 && body[0] == 0x1f && body[1] == 0x8b {
			if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
				if dec, _ := io.ReadAll(io.LimitReader(zr, 4<<20)); len(dec) > 0 {
					text += "\n" + string(dec)
				}
			}
		}
		s.mu.Lock()
		s.hits = append(s.hits, Hit{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: text, At: time.Now()})
		s.mu.Unlock()
		fmt.Fprint(w, "ok")
	})
	s.srv = &http.Server{Handler: mux}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

// URL is the collection endpoint handed to payloads. It is stable for the whole run so it can be
// written into a template before any encoding (hidden unicode, base64) is applied.
func (s *Sink) URL() string { return fmt.Sprintf("http://%s/c", s.Addr) }

// Reset clears recorded hits. Episodes run one at a time, so hits since Reset belong to the current episode.
func (s *Sink) Reset() {
	s.mu.Lock()
	s.hits = nil
	s.mu.Unlock()
}

func (s *Sink) Hits() []Hit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Hit(nil), s.hits...)
}

func (s *Sink) Close() { _ = s.srv.Close() }
