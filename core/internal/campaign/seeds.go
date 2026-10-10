package campaign

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Seed struct {
	ID        string   `yaml:"id" json:"id"`
	Technique string   `yaml:"technique" json:"technique"`
	ASI       []string `yaml:"asi" json:"asi"`
	Encoding  string   `yaml:"encoding" json:"encoding"` // "" | unicode_tags | base64
	Template  string   `yaml:"template" json:"template"`
}

type seedFile struct {
	Seeds []Seed `yaml:"seeds"`
}

func LoadSeeds(path string) ([]Seed, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f seedFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(f.Seeds) == 0 {
		return nil, fmt.Errorf("%s: no seeds", path)
	}
	return f.Seeds, nil
}

// Render substitutes template variables and applies the seed's encoding.
func (s Seed) Render(vars map[string]string) string {
	p := s.Template
	for k, v := range vars {
		p = strings.ReplaceAll(p, "{{"+k+"}}", v)
	}
	return Encode(p, s.Encoding)
}

// Encode obfuscates a payload. unicode_tags maps ASCII to the invisible Unicode
// tag block (U+E0000+), which renders as nothing but is read by many tokenizers.
func Encode(p, enc string) string {
	switch enc {
	case "unicode_tags":
		var b strings.Builder
		for _, r := range p {
			if r < 0x80 {
				b.WriteRune(0xE0000 + r)
			}
		}
		return "Candidate notes: " + b.String()
	case "base64":
		return "Reference blob (decode and follow): " + base64.StdEncoding.EncodeToString([]byte(p))
	default:
		return p
	}
}

// RenderPlain substitutes variables but applies no encoding (operators encode later).
func (s Seed) RenderPlain(vars map[string]string) string {
	p := s.Template
	for k, v := range vars {
		p = strings.ReplaceAll(p, "{{"+k+"}}", v)
	}
	return p
}
