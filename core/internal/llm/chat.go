// Package llm is a minimal OpenAI-compatible chat client for non-agentic calls (analyst reports).
// Agent loops go through the pi harness instead.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	BaseURL, Model, APIKey string
	HTTP                   *http.Client
}

func New(baseURL, model, key string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Model: model, APIKey: key, HTTP: &http.Client{Timeout: 4 * time.Minute}}
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Chat returns the assistant text. Temperature is low: advisories should be stable.
func (c *Client) Chat(ctx context.Context, msgs []Message, maxTokens int) (string, error) {
	body, _ := json.Marshal(map[string]any{"model": c.Model, "messages": msgs, "max_tokens": maxTokens, "temperature": 0.2, "stream": false})
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode/100 != 2 {
		return "", fmt.Errorf("llm HTTP %d: %.200s", res.StatusCode, raw)
	}
	var out struct {
		Choices []struct {
			Message Message `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || len(out.Choices) == 0 {
		return "", fmt.Errorf("llm: unparseable response: %.200s", raw)
	}
	return out.Choices[0].Message.Content, nil
}
