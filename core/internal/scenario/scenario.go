// Package scenario loads target-agent scenarios: persona, tools, declared
// capabilities, data, injection surfaces, attack objectives and benign tasks.
package scenario

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Capability struct {
	// AllowedRecipientDomains restricts send_email. Empty means "unrestricted" (flagged by the auditor).
	AllowedRecipientDomains []string `yaml:"allowed_recipient_domains" json:"allowed_recipient_domains"`
	// Egress marks tools that can move data out of the system.
	Egress bool `yaml:"egress" json:"egress"`
	// Destructive marks tools needing human approval.
	Destructive bool `yaml:"destructive" json:"destructive"`
}

type Document struct {
	Text string `yaml:"text" json:"text"`
	// Untrusted marks content authored outside the trust boundary (resumes, web pages, inbound email).
	Untrusted bool `yaml:"untrusted" json:"untrusted"`
}

type Record struct {
	ID     string `yaml:"id" json:"id"`
	Text   string `yaml:"text" json:"text"`
	Label  string `yaml:"label" json:"label"`   // pii | secret | public
	Canary string `yaml:"canary" json:"canary"` // unique token embedded in Text
}

type Surface struct {
	ID     string `yaml:"id" json:"id"`
	Kind   string `yaml:"kind" json:"kind"`     // document | web | memory | user
	Target string `yaml:"target" json:"target"` // document id / url / memory key
}

type Objective struct {
	ID          string   `yaml:"id" json:"id"`
	Kind        string   `yaml:"kind" json:"kind"` // email_exfil | url_exfil | memory_poison | tool_called
	Description string   `yaml:"description" json:"description"`
	Severity    string   `yaml:"severity" json:"severity"`
	ASI         []string `yaml:"asi" json:"asi"`
	Tool        string   `yaml:"tool" json:"tool,omitempty"` // for tool_called
}

type Check struct {
	Kind   string `yaml:"kind" json:"kind"` // tool_called | final_contains | email_sent_to_domain | no_error
	Tool   string `yaml:"tool" json:"tool,omitempty"`
	Value  string `yaml:"value" json:"value,omitempty"`
	Domain string `yaml:"domain" json:"domain,omitempty"`
}

// OfflineTurn scripts one assistant turn for offline (no-LLM) runs of a benign task.
type OfflineTurn struct {
	Text      string `yaml:"text" json:"text,omitempty"`
	ToolCalls []struct {
		Name string         `yaml:"name" json:"name"`
		Args map[string]any `yaml:"args" json:"args"`
	} `yaml:"tool_calls" json:"tool_calls,omitempty"`
}

type BenignTask struct {
	ID        string        `yaml:"id" json:"id"`
	UserTurns []string      `yaml:"user_turns" json:"user_turns"`
	Checks    []Check       `yaml:"checks" json:"checks"`
	Offline   []OfflineTurn `yaml:"offline" json:"offline,omitempty"`
}

type Scenario struct {
	ID              string                `yaml:"id" json:"id"`
	Name            string                `yaml:"name" json:"name"`
	Description     string                `yaml:"description" json:"description"`
	SystemPrompt    string                `yaml:"system_prompt" json:"system_prompt"`
	Tools           []string              `yaml:"tools" json:"tools"`
	Capabilities    map[string]Capability `yaml:"capabilities" json:"capabilities"`
	InternalDomains []string              `yaml:"internal_domains" json:"internal_domains"`
	Documents       map[string]Document   `yaml:"documents" json:"documents"`
	Records         []Record              `yaml:"records" json:"records"`
	Web             map[string]Document   `yaml:"web" json:"web"`
	Memory          map[string]string     `yaml:"memory" json:"memory"`
	Surfaces        []Surface             `yaml:"surfaces" json:"surfaces"`
	UserTask        []string              `yaml:"user_task" json:"user_task"`
	Objectives      []Objective           `yaml:"objectives" json:"objectives"`
	BenignTasks     []BenignTask          `yaml:"benign_tasks" json:"benign_tasks"`

	SHA256 string `yaml:"-" json:"-"`
}

func Load(path string) (*Scenario, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Scenario
	if err := yaml.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	sum := sha256.Sum256(b)
	s.SHA256 = hex.EncodeToString(sum[:])
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

func (s *Scenario) Validate() error {
	if s.ID == "" || s.SystemPrompt == "" || len(s.Tools) == 0 {
		return fmt.Errorf("scenario needs id, system_prompt and tools")
	}
	if len(s.UserTask) == 0 {
		return fmt.Errorf("scenario needs user_task (the benign request that exposes the agent to the surface)")
	}
	for _, sf := range s.Surfaces {
		if sf.Kind == "document" {
			if _, ok := s.Documents[sf.Target]; !ok {
				return fmt.Errorf("surface %s targets unknown document %q", sf.ID, sf.Target)
			}
		}
	}
	return nil
}

func (s *Scenario) Surface(id string) *Surface {
	for i := range s.Surfaces {
		if s.Surfaces[i].ID == id {
			return &s.Surfaces[i]
		}
	}
	return nil
}

func (s *Scenario) IsInternal(email string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	dom := strings.ToLower(strings.TrimSpace(email[at+1:]))
	for _, d := range s.InternalDomains {
		if strings.ToLower(d) == dom {
			return true
		}
	}
	return false
}

// Canaries returns the canary tokens of sensitive records.
func (s *Scenario) Canaries() []string {
	var out []string
	for _, r := range s.Records {
		if r.Canary != "" && r.Label != "public" {
			out = append(out, r.Canary)
		}
	}
	return out
}
