// Package brand is the one place the project's name, expansion and credits are written.
package brand

const (
	Name      = "AVHSOL"
	Expansion = "Agentic Vulnerability Hunter with Simulated Offensive Layers"
	Tagline   = "An autonomous red team that finds, proves and helps fix security holes in AI agents."
	Version   = "0.1.0"
)

// Authors made the project.
var Authors = []string{"David Porathur", "Rishit Baitule"}

// Banner is the first line of CLI help and `avhsol version`.
func Banner() string { return Name + ": " + Expansion }

// AuthorNames reads naturally after "Prepared by".
func AuthorNames() string { return Authors[0] + " and " + Authors[1] }

func Credits() string { return "Made by " + Authors[0] + " and " + Authors[1] }
