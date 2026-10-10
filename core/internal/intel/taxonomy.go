package intel

import (
	_ "embed"
	"sort"

	"gopkg.in/yaml.v3"
)

//go:embed data/taxonomy.yaml
var taxonomyYAML []byte

// Technique is one AVHSOL attack technique with its public taxonomy ids.
type Technique struct {
	Title    string   `yaml:"title" json:"title"`
	OWASPLLM []string `yaml:"owasp_llm" json:"owasp_llm"`
	ASI      []string `yaml:"asi" json:"asi"`
	ATLAS    []string `yaml:"atlas" json:"atlas"`
}

// Taxonomy maps technique names to taxonomy ids.
type Taxonomy struct {
	Version    string               `yaml:"version" json:"version"`
	Techniques map[string]Technique `yaml:"techniques" json:"techniques"`
}

// LoadTaxonomy returns the embedded taxonomy.
func LoadTaxonomy() (*Taxonomy, error) {
	var t Taxonomy
	if err := yaml.Unmarshal(taxonomyYAML, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// IDs returns every taxonomy id for a technique, sorted.
func (t *Taxonomy) IDs(technique string) []string {
	tc, ok := t.Techniques[technique]
	if !ok {
		return nil
	}
	return uniq(append(append(append([]string{}, tc.OWASPLLM...), tc.ASI...), tc.ATLAS...))
}

// Techniques lists the known technique names.
func (t *Taxonomy) Names() []string {
	var out []string
	for k := range t.Techniques {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Annotate fills Tags and Taxon on an item from its text.
func (t *Taxonomy) Annotate(i *Item) {
	i.Tags = append(i.Tags, Relevance(i)...)
	for _, tech := range TechniquesOf(i) {
		i.Tags = append(i.Tags, "technique:"+tech)
		i.Taxon = append(i.Taxon, t.IDs(tech)...)
	}
	i.Tags = uniq(i.Tags)
	i.Taxon = uniq(i.Taxon)
}
