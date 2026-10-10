package export

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Formats AVHSOL can produce.
var Formats = []string{"html", "pdf", "md", "json", "sarif"}

// Generate builds the report from a run directory and renders it with a skeleton. skeleton is a
// built-in name or a file path; it is ignored for json and sarif, which are not layout-driven.
func Generate(o Options, skeleton, format string) (body []byte, contentType string, err error) {
	r, err := Build(o)
	if err != nil {
		return nil, "", err
	}
	switch format {
	case "json":
		b, err := JSON(r)
		return b, "application/json", err
	case "sarif":
		b, err := SARIF(r)
		return b, "application/sarif+json", err
	case "html", "md", "pdf":
		sk, err := LoadSkeleton(skeleton)
		if err != nil {
			return nil, "", err
		}
		data, err := ToData(r)
		if err != nil {
			return nil, "", err
		}
		doc, err := Compile(sk, data)
		if err != nil {
			return nil, "", err
		}
		switch format {
		case "md":
			return RenderMarkdown(doc), "text/markdown; charset=utf-8", nil
		case "html":
			return RenderHTML(doc), "text/html; charset=utf-8", nil
		}
		b, err := htmlToPDF(RenderHTML(doc))
		return b, "application/pdf", err
	}
	return nil, "", fmt.Errorf("unknown format %q (use %s)", format, strings.Join(Formats, ", "))
}

// chromePath finds a Chrome/Chromium binary for PDF output.
func chromePath() string {
	for _, p := range []string{os.Getenv("AVHSOL_CHROME"), "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"} {
		if p == "" {
			continue
		}
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
	}
	return ""
}

// PDFAvailable reports whether PDF output can work on this machine.
func PDFAvailable() bool { return chromePath() != "" }

func htmlToPDF(html []byte) ([]byte, error) {
	chrome := chromePath()
	if chrome == "" {
		return nil, fmt.Errorf("PDF output needs Chrome or Chromium (set AVHSOL_CHROME), or open the HTML report and print it to PDF")
	}
	dir, err := os.MkdirTemp("", "avhsol-pdf-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	in, out := filepath.Join(dir, "report.html"), filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(in, html, 0o600); err != nil {
		return nil, err
	}
	cmd := exec.Command(chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--no-pdf-header-footer",
		"--user-data-dir="+filepath.Join(dir, "profile"), "--print-to-pdf="+out, "file://"+in)
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("chrome failed: %w", err)
		}
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("chrome timed out rendering the PDF")
	}
	return os.ReadFile(out)
}
