package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxBody = 16 << 20 // no feed gets to make us read more than this

// Client does the HTTP for every source: HTTPS only (plain HTTP is allowed to loopback for tests), bounded bodies,
// bounded time, a fixed User-Agent, and no redirects to other schemes.
type Client struct {
	HTTP *http.Client
}

func NewClient() *Client {
	return &Client{HTTP: &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return fmt.Errorf("too many redirects")
			}
			return checkURL(req.URL)
		},
	}}
}

func checkURL(u *url.URL) error {
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		h := u.Hostname()
		if h == "localhost" || net.ParseIP(h).IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("refusing non-HTTPS URL %s://%s", u.Scheme, u.Host)
}

func (c *Client) do(ctx context.Context, method, rawurl string, body io.Reader, hdr map[string]string) ([]byte, http.Header, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, nil, err
	}
	if err := checkURL(u); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, rawurl, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "avhsol-intel/1 (+https://github.com/41vi4p/avhsol)")
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > maxBody {
		return nil, nil, fmt.Errorf("%s: response larger than %d bytes", u.Host, maxBody)
	}
	if res.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("%s: HTTP %d: %s", u.Host, res.StatusCode, firstLine(string(b)))
	}
	return b, res.Header, nil
}

func (c *Client) getJSON(ctx context.Context, rawurl string, hdr map[string]string, into any) (http.Header, error) {
	b, h, err := c.do(ctx, "GET", rawurl, nil, hdr)
	if err != nil {
		return nil, err
	}
	return h, json.Unmarshal(b, into)
}

func (c *Client) postJSON(ctx context.Context, rawurl string, payload, into any) error {
	pb, _ := json.Marshal(payload)
	b, _, err := c.do(ctx, "POST", rawurl, strings.NewReader(string(pb)), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

// sleep waits d (a source's own politeness delay), or until the context ends.
func sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
