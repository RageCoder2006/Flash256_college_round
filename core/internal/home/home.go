// Package home finds where AVHSOL's assets (scenarios, seeds, target templates, helper binaries) and its per-user
// state (signing key, threat-intel cache, run directories) live, so the same binary works from a repository
// checkout and from a user-level install (scripts/install.sh) without any repo-relative path.
package home

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// assetDirs are the directories that identify an AVHSOL asset root.
var assetDirs = []string{"scenarios", "seeds", "targets"}

func isAssetRoot(dir string) bool {
	for _, d := range assetDirs {
		if st, err := os.Stat(filepath.Join(dir, d)); err != nil || !st.IsDir() {
			return false
		}
	}
	return true
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if rp, err := filepath.EvalSymlinks(exe); err == nil {
		exe = rp
	}
	return filepath.Dir(exe)
}

func userHome() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}

// Assets is the directory holding scenarios/, seeds/ and targets/: $AVHSOL_HOME, the share directory of an installed
// copy (<prefix>/share/avhsol next to <prefix>/bin), or the repository checkout (found upward from the working
// directory, then from the executable). It is "" when none is found.
func Assets() string {
	if h := os.Getenv("AVHSOL_HOME"); h != "" {
		return h
	}
	if d := exeDir(); d != "" {
		if s := filepath.Join(filepath.Dir(d), "share", "avhsol"); isAssetRoot(s) {
			return s
		}
	}
	if r := Checkout(); r != "" {
		return r
	}
	if s := filepath.Join(userHome(), ".local", "share", "avhsol"); isAssetRoot(s) {
		return s
	}
	return ""
}

// Checkout is the repository root when running from a source checkout ("" otherwise).
func Checkout() string {
	if d := exeDir(); d != "" && os.Getenv("AVHSOL_HOME") == "" {
		if isAssetRoot(filepath.Join(filepath.Dir(d), "share", "avhsol")) {
			return "" // an installed binary: the working directory happening to sit inside a checkout changes nothing
		}
	}
	var starts []string
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}
	if d := exeDir(); d != "" {
		starts = append(starts, d)
	}
	for _, s := range starts {
		for dir := s; ; dir = filepath.Dir(dir) {
			if isAssetRoot(dir) {
				if _, err := os.Stat(filepath.Join(dir, "core", "go.mod")); err == nil {
					return dir
				}
			}
			if filepath.Dir(dir) == dir {
				break
			}
		}
	}
	return ""
}

// Installed reports whether the binary runs from a user-level install rather than a checkout.
func Installed() bool { return Checkout() == "" }

// ConfigDir holds the signing key and stack.env: $AVHSOL_CONFIG, deploy/stack in a checkout, else ~/.config/avhsol.
func ConfigDir() string {
	if d := os.Getenv("AVHSOL_CONFIG"); d != "" {
		return d
	}
	if r := Checkout(); r != "" {
		return filepath.Join(r, "deploy", "stack")
	}
	return filepath.Join(userHome(), ".config", "avhsol")
}

// StateDir holds run directories and the threat-intel cache: $AVHSOL_STATE, the checkout itself, else ~/.local/share/avhsol.
func StateDir() string {
	if d := os.Getenv("AVHSOL_STATE"); d != "" {
		return d
	}
	if r := Checkout(); r != "" {
		return r
	}
	return filepath.Join(userHome(), ".local", "share", "avhsol")
}

// SigningKey is the default trace-signing key path.
func SigningKey() string { return filepath.Join(ConfigDir(), "signing.key") }

// IntelDir is the default threat-intel cache.
func IntelDir() string {
	if r := Checkout(); r != "" && os.Getenv("AVHSOL_STATE") == "" {
		return filepath.Join(r, "deploy", "stack", "intel")
	}
	return filepath.Join(StateDir(), "intel")
}

// Bin finds a helper binary (avhsol-proxy, avhsol-sandbox): next to the executable, in the checkout's guard build, or on PATH.
func Bin(name string) string {
	if d := exeDir(); d != "" {
		if p := filepath.Join(d, name); isFile(p) {
			return p
		}
	}
	if r := Checkout(); r != "" {
		if p := filepath.Join(r, "guard", "target", "release", name); isFile(p) {
			return p
		}
	}
	if p, err := lookPath(name); err == nil {
		return p
	}
	if r := Checkout(); r != "" {
		return filepath.Join(r, "guard", "target", "release", name)
	}
	return name
}

// Resolve maps an asset path such as scenarios/devops-coder.yaml to a file that exists: the path itself when it
// exists relative to the working directory, else the same path under Assets(). Absolute paths and unknown paths are returned unchanged.
func Resolve(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if a := Assets(); a != "" {
		if q := filepath.Join(a, p); exists(q) {
			return q
		}
	}
	return p
}

// HarnessDir is the pi harness (pi/packages/avhsol) when one is available: next to the assets or in the checkout.
func HarnessDir() string {
	for _, base := range []string{os.Getenv("AVHSOL_HARNESS_DIR"), Assets()} {
		if base == "" {
			continue
		}
		for _, cand := range []string{filepath.Join(base, "pi"), base} {
			if exists(filepath.Join(cand, "packages", "avhsol", "src", "rpc.ts")) {
				return cand
			}
		}
	}
	return ""
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func lookPath(name string) (string, error) {
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if d == "" {
			continue
		}
		p := filepath.Join(d, name)
		if isFile(p) {
			return p, nil
		}
	}
	return "", os.ErrNotExist
}

// Slug turns a directory name into a safe run-directory component.
func Slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "agent"
	}
	return out
}
