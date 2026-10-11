package whitebox

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxFiles    = 6000
	maxFileSize = 600 << 10
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "dist": true, "build": true, "target": true, "venv": true, ".venv": true, "env": false,
	"__pycache__": true, "vendor": true, ".next": true, ".tox": true, ".mypy_cache": true, ".pytest_cache": true, "coverage": true, ".cache": true,
	"site-packages": true, ".gradle": true, ".idea": true, ".vscode": true,
}

var codeExt = map[string]string{
	".py": "Python", ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
	".go": "Go", ".rs": "Rust", ".java": "Java", ".rb": "Ruby",
}

// file is a source or config file read into memory.
type file struct {
	Rel   string
	Lang  string
	Lines []string
	Test  bool
}

func isTestPath(rel string) bool {
	l := strings.ToLower(rel)
	for _, s := range []string{"/test/", "/tests/", "/__tests__/", "/testdata/", "/fixtures/", "/examples/", "/example/", "/docs/", "/e2e/", "/evals/"} {
		if strings.Contains("/"+l, s) {
			return true
		}
	}
	b := filepath.Base(l)
	return strings.HasPrefix(b, "test_") || strings.HasSuffix(b, "_test.go") || strings.Contains(b, ".test.") || strings.Contains(b, ".spec.") || strings.HasSuffix(b, "_test.py")
}

// walk lists the files worth reading, without following symlinks out of the tree.
func walk(root string) (code []*file, other map[string]string, warns []string, err error) {
	other = map[string]string{}
	n := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			if rel != "." && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() > maxFileSize {
			return nil
		}
		base := d.Name()
		ext := strings.ToLower(filepath.Ext(base))
		lang, isCode := codeExt[ext]
		interesting := isCode || isManifest(base) || isInstructionFile(base) || strings.HasPrefix(base, ".env") || isMCPConfig(rel)
		if !interesting {
			return nil
		}
		n++
		if n > maxFiles {
			if n == maxFiles+1 {
				warns = append(warns, "stopped after reading the first files: the tree is large; findings may be incomplete")
			}
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		if isCode {
			code = append(code, &file{Rel: filepath.ToSlash(rel), Lang: lang, Lines: strings.Split(string(b), "\n"), Test: isTestPath(rel)})
		}
		other[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	return
}

func isManifest(b string) bool {
	switch b {
	case "package.json", "package-lock.json", "requirements.txt", "pyproject.toml", "Pipfile", "go.mod", "Cargo.toml", "Cargo.lock", "poetry.lock", "uv.lock":
		return true
	}
	return strings.HasPrefix(b, "requirements") && strings.HasSuffix(b, ".txt")
}

func isInstructionFile(b string) bool {
	switch strings.ToLower(b) {
	case "agents.md", "claude.md", ".cursorrules", "gemini.md", "copilot-instructions.md", "readme.md", "contributing.md":
		return true
	}
	return false
}

func isMCPConfig(rel string) bool {
	r := filepath.ToSlash(strings.ToLower(rel))
	b := filepath.Base(r)
	return b == ".mcp.json" || b == "mcp.json" || b == "claude_desktop_config.json" || strings.HasSuffix(r, ".cursor/mcp.json") || strings.HasSuffix(r, ".vscode/mcp.json")
}
