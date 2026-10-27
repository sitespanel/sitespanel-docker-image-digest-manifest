package manifest

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// Runner runs a shell script inside an image, pulled by digest.
type Runner interface {
	Run(ctx context.Context, ref, script string) (string, error)
	// Remove frees the disk the image used once it is checked.
	Remove(ctx context.Context, ref string)
}

// Docker runs scripts with the docker command line.
type Docker struct{ Program string }

func (d Docker) Run(ctx context.Context, ref, script string) (string, error) {
	cmd := exec.CommandContext(ctx, d.Program, "run", "--rm", "--pull", "missing", "--platform", "linux/amd64",
		"--network", "none", "--entrypoint", "sh", ref, "-c", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("docker run %s: %v: %s", ref, err, strings.TrimSpace(tail(stderr.String(), 2000)))
	}
	return string(out), nil
}

func (d Docker) Remove(ctx context.Context, ref string) {
	_ = exec.CommandContext(ctx, d.Program, "image", "rm", "--force", ref).Run()
}

// checkContract returns what the image lacks (empty when it holds), and
// the PHP extensions when the contract records them.
func checkContract(ctx context.Context, run Runner, ref string, c Contract) (problems, extensions []string, err error) {
	if len(c.Paths)+len(c.Absent) > 0 {
		var script strings.Builder
		for _, p := range c.Paths {
			fmt.Fprintf(&script, "test -e %s || echo missing %s\n", shellQuote(p), shellQuote(p))
		}
		for _, p := range c.Absent {
			fmt.Fprintf(&script, "test -e %s && echo present %s\n", shellQuote(p), shellQuote(p))
		}
		script.WriteString("true\n")
		out, err := run.Run(ctx, ref, script.String())
		if err != nil {
			return nil, nil, err
		}
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			switch {
			case strings.HasPrefix(l, "missing "):
				problems = append(problems, "lacks "+strings.TrimPrefix(l, "missing "))
			case strings.HasPrefix(l, "present "):
				problems = append(problems, "must not contain "+strings.TrimPrefix(l, "present "))
			}
		}
	}
	for _, o := range c.Outputs {
		out, err := run.Run(ctx, ref, o.Command+" 2>&1")
		if err != nil {
			return nil, nil, err
		}
		have := words(out)
		for _, want := range o.Contains {
			if !have[want] && !lines(out)[want] {
				problems = append(problems, fmt.Sprintf("`%s` does not show %s", o.Command, want))
			}
		}
	}
	if c.RecordPHPExtensions {
		out, err := run.Run(ctx, ref, "php -m")
		if err != nil {
			return nil, nil, err
		}
		seen := map[string]bool{}
		for l := range lines(out) {
			if l != "" && !strings.HasPrefix(l, "[") && !seen[l] {
				seen[l] = true
				extensions = append(extensions, l)
			}
		}
		sort.Strings(extensions)
	}
	return problems, extensions, nil
}

func words(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

func lines(s string) map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		m[strings.TrimSpace(l)] = true
	}
	return m
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
