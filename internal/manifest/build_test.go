package manifest

import (
	"context"
	"strings"
	"testing"
	"time"
)

type fakeRegistry map[string]string // "repository:tag" -> digest

func (f fakeRegistry) Digest(_ context.Context, repo, tag string) (string, error) {
	return f[repo+":"+tag], nil
}

type fakeScanner struct {
	findings map[string][]Finding // ref -> findings
	scanned  []string
}

func (f *fakeScanner) Scan(_ context.Context, ref string) ([]Finding, error) {
	f.scanned = append(f.scanned, ref)
	return f.findings[ref], nil
}

type fakeRunner struct {
	files   map[string]bool   // paths present in every image
	outputs map[string]string // command -> output
	removed []string
}

// Run answers the contract's path script from files, and commands from
// outputs.
func (f *fakeRunner) Run(_ context.Context, ref, script string) (string, error) {
	if !strings.HasPrefix(script, "test -e") {
		return f.outputs[strings.TrimSuffix(script, " 2>&1")], nil
	}
	var out strings.Builder
	for _, l := range strings.Split(script, "\n") {
		w := strings.Fields(l) // test -e 'p' (||/&&) echo missing/present 'p'
		if len(w) != 7 {
			continue
		}
		p := strings.Trim(w[2], "'")
		if (w[3] == "||") != f.files[p] {
			out.WriteString(w[5] + " " + p + "\n")
		}
	}
	return out.String(), nil
}

func (f *fakeRunner) Remove(_ context.Context, ref string) { f.removed = append(f.removed, ref) }

var now = time.Date(2026, 10, 27, 6, 0, 0, 0, time.UTC)

func phpImage() Image {
	return Image{Name: "php-fpm", Version: "8.4", Repository: "easydigital/php", Tag: "8.4-fpm-trixie", FirstParty: true,
		Contract: Contract{
			Outputs:             []Output{{Command: "php -m", Contains: []string{"mysqli", "redis", "Zend OPcache"}}},
			RecordPHPExtensions: true,
		}}
}

func mariadbImage() Image {
	return Image{Name: "mariadb", Version: "11.8", Repository: "library/mariadb", Tag: "11.8-noble"}
}

const phpM = "[PHP Modules]\nmysqli\nredis\nZend OPcache\n\n[Zend Modules]\nZend OPcache\n"

func builder(images ...Image) (Builder, *fakeScanner, *fakeRunner) {
	sc := &fakeScanner{findings: map[string][]Finding{}}
	run := &fakeRunner{outputs: map[string]string{"php -m": phpM}}
	return Builder{
		Config:   Config{Images: images},
		Registry: fakeRegistry{"easydigital/php:8.4-fpm-trixie": d1, "library/mariadb:11.8-noble": d1, "easydigital/nginx:1.30.5": d1},
		Scanner:  sc, Runner: run, Now: now,
	}, sc, run
}

// TEST-274: the pipeline records pinned digests in the manifest and checks
// the PHP extension list.
func TestBuildRecordsDigestsAndPHPExtensions(t *testing.T) {
	b, _, run := builder(phpImage(), mariadbImage())
	m, rep, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Images) != 2 || len(rep.Unlisted) != 0 {
		t.Fatalf("images %+v, report %+v", m.Images, rep)
	}
	php, _ := m.Find("php-fpm", "8.4")
	if php.Ref() != "docker.io/easydigital/php@"+d1 || strings.Join(php.PHPExtensions, ",") != "Zend OPcache,mysqli,redis" {
		t.Fatalf("php entry %+v", php)
	}
	if len(run.removed) != 1 {
		t.Fatalf("checked images are removed after the contract: %v", run.removed)
	}
	if m.Sequence != now.Unix() || !m.ExpiresAt.Equal(now.Add(Validity)) {
		t.Fatalf("sequence %d expires %v", m.Sequence, m.ExpiresAt)
	}

	// An extension missing from a rebuild keeps the digest out.
	b, _, run = builder(phpImage())
	run.outputs["php -m"] = "[PHP Modules]\nmysqli\nZend OPcache\n"
	m, rep, err = b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Images) != 0 || len(rep.Unlisted) != 1 || !strings.Contains(strings.Join(rep.Lines, "\n"), "does not show redis") {
		t.Fatalf("missing extension: %+v %+v", m.Images, rep)
	}
}

func TestContractPathsAndAbsent(t *testing.T) {
	nginx := Image{Name: "nginx", Version: "1.30.5", Repository: "easydigital/nginx", Tag: "1.30.5", FirstParty: true,
		Contract: Contract{
			Paths:   []string{"/usr/lib/nginx/modules/ngx_http_modsecurity_module.so", "/usr/bin/setfacl"},
			Absent:  []string{"/usr/bin/supervisord"},
			Outputs: []Output{{Command: "nginx -V", Contains: []string{"--with-http_v3_module"}}},
		}}
	b, _, run := builder(nginx)
	run.files = map[string]bool{"/usr/bin/setfacl": true, "/usr/bin/supervisord": true}
	run.outputs["nginx -V"] = "nginx version: nginx/1.30.5\nconfigure arguments: --with-http_realip_module --with-http_v3_module"
	m, rep, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(rep.Lines, "\n")
	if len(m.Images) != 0 || !strings.Contains(got, "lacks /usr/lib/nginx/modules/ngx_http_modsecurity_module.so") ||
		!strings.Contains(got, "must not contain /usr/bin/supervisord") || strings.Contains(got, "setfacl") || strings.Contains(got, "http_v3") {
		t.Fatalf("report %s", got)
	}
	run.files["/usr/lib/nginx/modules/ngx_http_modsecurity_module.so"] = true
	delete(run.files, "/usr/bin/supervisord")
	if m, _, _ = b.Build(context.Background()); len(m.Images) != 1 {
		t.Fatal("a complete image was not approved")
	}
}

func TestBuildNeedsApprovedWaivers(t *testing.T) {
	ref := "docker.io/library/mariadb@" + d1
	finding := Finding{ID: "CVE-2025-68121", Package: "stdlib", Installed: "1.24", Fixed: "1.25", Severity: "CRITICAL"}

	b, sc, _ := builder(mariadbImage())
	sc.findings[ref] = []Finding{finding}
	b.Waivers = Waivers{Waivers: []Waiver{{Image: "mariadb", ID: finding.ID, Approved: "proposed", Expires: "2026-11-26", Reason: "gosu is never run"}}}
	m, rep, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Images) != 0 || rep.Unlisted[0] != "mariadb 11.8" || !strings.Contains(strings.Join(rep.Lines, "\n"), "waiver proposed") {
		t.Fatalf("a proposed waiver let it in: %+v %+v", m.Images, rep)
	}

	b.Waivers.Waivers[0].Approved = "2026-10-27"
	m, rep, err = b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e, ok := m.Find("mariadb", "11.8")
	if !ok || len(e.Waived) != 1 || e.Waived[0] != finding.ID || len(rep.Unlisted) != 0 {
		t.Fatalf("an approved waiver: %+v %+v", m.Images, rep)
	}
}

func TestBuildKeepsTheLastApprovedDigest(t *testing.T) {
	b, sc, _ := builder(mariadbImage())
	first, _, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Six hours later: unchanged, so nothing is scanned again.
	b.Previous, b.Now, sc.scanned = &first, now.Add(6*time.Hour), nil
	second, _, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.scanned) != 0 || second.Sequence <= first.Sequence {
		t.Fatalf("scanned %v, sequence %d after %d", sc.scanned, second.Sequence, first.Sequence)
	}

	// The tag moves to a digest with an unwaived finding: the old digest
	// stays listed and the new one is reported.
	b.Registry = fakeRegistry{"library/mariadb:11.8-noble": d2}
	sc.findings["docker.io/library/mariadb@"+d2] = []Finding{{ID: "CVE-X", Severity: "HIGH", Fixed: "2"}}
	third, rep, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := third.Find("mariadb", "11.8")
	if e.Digest != d1 || !strings.Contains(strings.Join(rep.Lines, "\n"), "not approved") {
		t.Fatalf("kept %s, report %v", e.Digest, rep.Lines)
	}

	// The daily re-scan finds something new in the listed digest: it stays
	// listed with its findings, for the panel to alert staff (TEST-416).
	b.Registry = fakeRegistry{"library/mariadb:11.8-noble": d1}
	b.Previous, b.RescanAll = &third, true
	sc.findings["docker.io/library/mariadb@"+d1] = []Finding{{ID: "CVE-Y", Severity: "CRITICAL", Fixed: "3"}}
	fourth, _, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e, _ = fourth.Find("mariadb", "11.8")
	if e.Digest != d1 || len(e.Findings) != 1 || e.Findings[0] != "CVE-Y" {
		t.Fatalf("re-scan: %+v", e)
	}

	// A repository change drops the old approval.
	moved := mariadbImage()
	moved.Repository = "sitespanel/mariadb"
	b.Config = Config{Images: []Image{moved}}
	b.Registry = fakeRegistry{"sitespanel/mariadb:11.8-noble": d1}
	b.Previous, b.RescanAll = &first, false
	sc.findings["docker.io/sitespanel/mariadb@"+d1] = []Finding{{ID: "CVE-Z", Severity: "HIGH", Fixed: "2"}}
	fifth, rep, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fifth.Images) != 0 || len(rep.Unlisted) != 1 {
		t.Fatalf("moved image kept an old approval: %+v", fifth.Images)
	}
}

func TestStaleWaiversAreReported(t *testing.T) {
	b, _, _ := builder(mariadbImage())
	b.Waivers = Waivers{Waivers: []Waiver{{Image: "mariadb", ID: "CVE-OLD", Approved: "2026-10-20", Expires: "2026-11-19", Reason: "x"}}}
	_, rep, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(rep.Lines, "\n"), "stale") {
		t.Fatal("stale is reported only after a full re-scan")
	}
	b.RescanAll = true
	_, rep, err = b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rep.Lines, "\n"), "waiver mariadb CVE-OLD: stale") {
		t.Fatalf("report %v", rep.Lines)
	}
}
