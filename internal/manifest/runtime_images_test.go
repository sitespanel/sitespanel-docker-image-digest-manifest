package manifest

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TEST-436 (TASK-0200): the manifest lists the runtime images of the Node.js and Python presets and the
// SSH clone image, each pinned to a version tag (never latest), with a contract that names what the stack relies on.
func TestRuntimeImages(t *testing.T) {
	cfg, err := LoadConfig("../../images.yaml")
	if err != nil {
		t.Fatal(err)
	}
	find := func(name, version string) Image {
		for _, im := range cfg.Images {
			if im.Name == name && im.Version == version {
				return im
			}
		}
		t.Fatalf("images.yaml has no %s %s", name, version)
		return Image{}
	}
	has := func(c Contract, p string) bool {
		for _, x := range c.Paths {
			if x == p {
				return true
			}
		}
		return false
	}
	for _, v := range []string{"22", "24", "26"} {
		run, build := find("node", v), find("node-build", v)
		if run.Repository != "library/node" || !strings.HasPrefix(run.Tag, v+"-") || !strings.HasSuffix(run.Tag, "-slim") || run.FirstParty {
			t.Errorf("node %s run entry: %+v", v, run)
		}
		if !has(run.Contract, "/usr/local/bin/node") || !has(run.Contract, "/usr/local/bin/npm") || len(run.Contract.Outputs) == 0 || run.Contract.Outputs[0].Contains[0] != v {
			t.Errorf("node %s run contract: %+v", v, run.Contract)
		}
		if !has(build.Contract, "/usr/bin/git") || !has(build.Contract, "/usr/bin/gcc") || strings.HasSuffix(build.Tag, "-slim") {
			t.Errorf("node %s build entry: %+v", v, build)
		}
	}
	for _, v := range []string{"3.12", "3.13", "3.14"} {
		run, build := find("python", v), find("python-build", v)
		if run.Repository != "library/python" || !strings.HasPrefix(run.Tag, v+"-slim") || !has(run.Contract, "/usr/local/bin/python3") || !has(run.Contract, "/usr/local/bin/pip") {
			t.Errorf("python %s run entry: %+v", v, run)
		}
		if !has(build.Contract, "/usr/bin/git") || !has(build.Contract, "/usr/bin/gcc") || strings.Contains(build.Tag, "slim") {
			t.Errorf("python %s build entry: %+v", v, build)
		}
	}
	if find("node", "24").SupportEnds != "2028-04-30" || find("python", "3.13").SupportEnds != "2029-10" || find("node-build", "26").SupportSource == "" {
		t.Error("the support end dates and their sources are not in images.yaml")
	}
	g := find("git-ssh", "2.54.0")
	if g.FirstParty || g.Repository != "alpine/git" || g.Tag != "2.54.0" || !has(g.Contract, "/usr/bin/git") || !has(g.Contract, "/usr/bin/ssh") {
		t.Errorf("git-ssh entry: %+v", g)
	}
	for _, im := range cfg.Images {
		if im.Tag == "latest" {
			t.Errorf("%s %s tracks latest", im.Name, im.Version)
		}
	}
	// The manifest key a server asks for is the name and version: no two runtime entries share one.
	seen := map[string]bool{}
	for _, im := range cfg.Images {
		k := im.Name + " " + im.Version
		if seen[k] {
			t.Errorf("%s is listed twice", k)
		}
		seen[k] = true
	}
}

// With SITESPANEL_TEST_IMAGE_REFS set ("node 24=node:24-trixie-slim;git-ssh 2.54.0=alpine/git:2.54.0"), each named entry's contract
// is run against that local image with the manifest's own checker. Nothing is pulled by the test.
func TestRuntimeImageContractsOnLocalImages(t *testing.T) {
	spec := os.Getenv("SITESPANEL_TEST_IMAGE_REFS")
	if spec == "" {
		t.Skip("SITESPANEL_TEST_IMAGE_REFS is not set")
	}
	cfg, err := LoadConfig("../../images.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, item := range strings.Split(spec, ";") {
		key, ref, ok := strings.Cut(item, "=")
		if !ok {
			t.Fatalf("bad item %q", item)
		}
		var im Image
		for _, c := range cfg.Images {
			if c.Name+" "+c.Version == key {
				im = c
			}
		}
		if im.Name == "" {
			t.Fatalf("no entry %q", key)
		}
		problems, _, err := checkContract(ctx, Docker{Program: "docker"}, ref, im.Contract)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if len(problems) > 0 {
			t.Errorf("%s does not hold its contract: %v", key, problems)
		}
	}
}

func TestSupportEndsNeedsADateAndASource(t *testing.T) {
	dir := t.TempDir()
	write := func(extra string) string {
		p := dir + "/images.yaml"
		body := "images:\n  - {name: node, version: \"24\", repository: library/node, tag: 24-trixie-slim" + extra + "}\n"
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := LoadConfig(write(", support_ends: \"2028-04-30\", support_source: \"nodejs\"")); err != nil {
		t.Errorf("a good entry was refused: %v", err)
	}
	for _, extra := range []string{", support_ends: \"2028-04-30\"", ", support_ends: \"soon\", support_source: \"x\""} {
		if _, err := LoadConfig(write(extra)); err == nil {
			t.Errorf("%s was accepted", extra)
		}
	}
}
