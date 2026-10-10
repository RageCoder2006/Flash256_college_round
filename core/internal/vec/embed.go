// Package vec holds the vector side of GraphRAG: embedders and a Qdrant client.
package vec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode"
)

// Embedder turns text into fixed-size vectors.
type Embedder interface {
	Name() string
	Dim() int
	Embed(ctx context.Context, texts []string) ([][]float32, error)
}

// HashEmbedder is an offline, deterministic, dependency-free lexical embedder (signed feature
// hashing of word unigrams/bigrams and character trigrams). It finds text that shares wording;
// it does NOT understand synonyms. Use HTTPEmbedder with a real model when meaning matters.
type HashEmbedder struct{ D int }

func NewHashEmbedder() *HashEmbedder { return &HashEmbedder{D: 384} }

func (h *HashEmbedder) Name() string { return fmt.Sprintf("hash-lexical-%d", h.D) }
func (h *HashEmbedder) Dim() int     { return h.D }

func tokens(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '@' && r != '.'
	})
}

func (h *HashEmbedder) add(v []float32, feature string, w float32) {
	f := fnv.New64a()
	_, _ = f.Write([]byte(feature))
	x := f.Sum64()
	idx := int(x % uint64(h.D))
	sign := float32(1)
	if (x>>40)&1 == 1 {
		sign = -1
	}
	v[idx] += sign * w
}

func (h *HashEmbedder) vector(text string) []float32 {
	v := make([]float32, h.D)
	ts := tokens(text)
	for i, t := range ts {
		h.add(v, "w:"+t, 1)
		if i+1 < len(ts) {
			h.add(v, "b:"+t+" "+ts[i+1], 0.7)
		}
		r := []rune("^" + t + "$")
		for j := 0; j+3 <= len(r); j++ {
			h.add(v, "c:"+string(r[j:j+3]), 0.3)
		}
	}
	var n float64
	for _, x := range v {
		n += float64(x) * float64(x)
	}
	if n == 0 {
		return v
	}
	n = math.Sqrt(n)
	for i := range v {
		v[i] = float32(float64(v[i]) / n)
	}
	return v
}

func (h *HashEmbedder) Embed(_ context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i, t := range texts {
		out[i] = h.vector(t)
	}
	return out, nil
}

// HTTPEmbedder calls an OpenAI-compatible /embeddings endpoint (text-embeddings-inference, Ollama,
// vLLM, ...). Run it locally so trace content never leaves the machine.
type HTTPEmbedder struct {
	BaseURL, Model, APIKey string
	D                      int
	HTTP                   *http.Client
}

func NewHTTPEmbedder(baseURL, model, key string) *HTTPEmbedder {
	return &HTTPEmbedder{BaseURL: strings.TrimRight(baseURL, "/"), Model: model, APIKey: key, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

func (e *HTTPEmbedder) Name() string { return "http:" + e.Model }
func (e *HTTPEmbedder) Dim() int     { return e.D }

func (e *HTTPEmbedder) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	body, _ := json.Marshal(map[string]any{"model": e.Model, "input": texts})
	req, err := http.NewRequestWithContext(ctx, "POST", e.BaseURL+"/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	if e.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+e.APIKey)
	}
	res, err := e.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("embeddings HTTP %d: %.200s", res.StatusCode, raw)
	}
	var out struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
			Index     int       `json:"index"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Data) != len(texts) {
		return nil, fmt.Errorf("embeddings: unexpected response: %.200s", raw)
	}
	vs := make([][]float32, len(texts))
	for _, d := range out.Data {
		if d.Index < 0 || d.Index >= len(vs) {
			return nil, fmt.Errorf("embeddings: bad index %d", d.Index)
		}
		vs[d.Index] = d.Embedding
	}
	if e.D == 0 && len(vs) > 0 {
		e.D = len(vs[0])
	}
	return vs, nil
}
