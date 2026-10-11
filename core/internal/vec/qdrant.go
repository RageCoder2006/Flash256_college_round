package vec

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Qdrant is a minimal REST client (no SDK dependency).
type Qdrant struct {
	BaseURL, APIKey string
	HTTP            *http.Client
}

func NewQdrant(baseURL, key string) *Qdrant {
	return &Qdrant{BaseURL: strings.TrimRight(baseURL, "/"), APIKey: key, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (q *Qdrant) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, q.BaseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("api-key", q.APIKey)
	res, err := q.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("qdrant %s %s: HTTP %d: %.300s", method, path, res.StatusCode, raw)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// EnsureCollection creates the collection if it does not exist (cosine distance).
func (q *Qdrant) EnsureCollection(ctx context.Context, name string, dim int) error {
	var info struct {
		Result struct {
			Config struct {
				Params struct {
					Vectors struct {
						Size int `json:"size"`
					} `json:"vectors"`
				} `json:"params"`
			} `json:"config"`
		} `json:"result"`
	}
	if err := q.do(ctx, "GET", "/collections/"+name, nil, &info); err == nil {
		if got := info.Result.Config.Params.Vectors.Size; got != dim {
			return fmt.Errorf("collection %s has dimension %d but the embedder produces %d: use a new collection or re-embed", name, got, dim)
		}
		return nil
	}
	return q.do(ctx, "PUT", "/collections/"+name, map[string]any{"vectors": map[string]any{"size": dim, "distance": "Cosine"}}, nil)
}

// PointID derives a stable UUID from a string id, so re-ingesting a trace overwrites instead of duplicating.
func PointID(id string) string {
	h := sha1.Sum([]byte("avhsol:" + id))
	h[6] = (h[6] & 0x0f) | 0x50
	h[8] = (h[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

type Point struct {
	ID      string
	Vector  []float32
	Payload map[string]any
}

func (q *Qdrant) Upsert(ctx context.Context, collection string, pts []Point) error {
	for start := 0; start < len(pts); start += 128 {
		end := start + 128
		if end > len(pts) {
			end = len(pts)
		}
		batch := make([]map[string]any, 0, end-start)
		for _, p := range pts[start:end] {
			batch = append(batch, map[string]any{"id": PointID(p.ID), "vector": p.Vector, "payload": p.Payload})
		}
		if err := q.do(ctx, "PUT", "/collections/"+collection+"/points?wait=true", map[string]any{"points": batch}, nil); err != nil {
			return err
		}
	}
	return nil
}

type Hit struct {
	Score   float32        `json:"score"`
	Payload map[string]any `json:"payload"`
}

// Search returns the nearest points. filter is a Qdrant "must" list of field matches (may be nil).
func (q *Qdrant) Search(ctx context.Context, collection string, vector []float32, limit int, must map[string]any) ([]Hit, error) {
	body := map[string]any{"vector": vector, "limit": limit, "with_payload": true}
	if len(must) > 0 {
		var conds []any
		for k, v := range must {
			conds = append(conds, map[string]any{"key": k, "match": map[string]any{"value": v}})
		}
		body["filter"] = map[string]any{"must": conds}
	}
	var out struct {
		Result []Hit `json:"result"`
	}
	if err := q.do(ctx, "POST", "/collections/"+collection+"/points/search", body, &out); err != nil {
		return nil, err
	}
	return out.Result, nil
}

// DeleteCollection removes a collection (used by `graph reset`).
func (q *Qdrant) DeleteCollection(ctx context.Context, name string) error {
	return q.do(ctx, "DELETE", "/collections/"+name, nil, nil)
}

// Health reports whether Qdrant answers its readiness probe.
func (q *Qdrant) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", q.BaseURL+"/readyz", nil)
	if err != nil {
		return err
	}
	req.Header.Set("api-key", q.APIKey)
	res, err := q.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("qdrant not ready: HTTP %d", res.StatusCode)
	}
	return nil
}
