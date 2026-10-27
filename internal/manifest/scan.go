package manifest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// Finding is one fixable high or critical vulnerability.
type Finding struct {
	ID        string
	Package   string
	Installed string
	Fixed     string
	Severity  string
}

// Trivy scans an image by reference with the Trivy command line. Command is
// the program and its leading arguments, for example a pinned Trivy image
// run by docker; tests use a stand-in.
type Trivy struct {
	Command []string
}

// Scan returns the fixable high and critical findings (the threshold of
// REQ-0069), one per ID, sorted.
func (t Trivy) Scan(ctx context.Context, ref string) ([]Finding, error) {
	args := append(append([]string{}, t.Command[1:]...),
		"image", "--quiet", "--format", "json", "--scanners", "vuln",
		"--severity", "HIGH,CRITICAL", "--ignore-unfixed",
		"--image-src", "remote", "--platform", "linux/amd64", ref)
	cmd := exec.CommandContext(ctx, t.Command[0], args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("trivy %s: %v: %s", ref, err, strings.TrimSpace(tail(stderr.String(), 2000)))
	}
	return parseTrivy(out)
}

func parseTrivy(out []byte) ([]Finding, error) {
	var report struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID  string
				PkgName          string
				InstalledVersion string
				FixedVersion     string
				Severity         string
			}
		}
	}
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("trivy output: %w", err)
	}
	byID := map[string]Finding{}
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			if v.FixedVersion == "" || (v.Severity != "HIGH" && v.Severity != "CRITICAL") {
				continue
			}
			if _, ok := byID[v.VulnerabilityID]; !ok {
				byID[v.VulnerabilityID] = Finding{ID: v.VulnerabilityID, Package: v.PkgName, Installed: v.InstalledVersion, Fixed: v.FixedVersion, Severity: v.Severity}
			}
		}
	}
	fs := make([]Finding, 0, len(byID))
	for _, f := range byID {
		fs = append(fs, f)
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].ID < fs[j].ID })
	return fs, nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
