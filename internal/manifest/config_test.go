package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// The repository's own files must load: a typo there would stop every run.
func TestRepositoryFilesLoad(t *testing.T) {
	cfg, err := LoadConfig("../../images.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWaivers("../../security/image-scan-waivers.yaml"); err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, im := range cfg.Images {
		have[im.Name] = true
		if im.FirstParty && !strings.HasPrefix(im.Repository, "easydigital/") {
			t.Errorf("%s: first-party images come from the company organisation (REQ-0068)", im.Name)
		}
		if im.Name == "php-fpm" && !im.Contract.RecordPHPExtensions {
			t.Errorf("php-fpm %s does not record its extensions (REQ-0028)", im.Version)
		}
		if im.Name == "php-fpm" && im.Version == "8.2" {
			t.Error("PHP 8.2 is not listed (ADR-0034)")
		}
	}
	// phpMyAdmin left the list on 2026-10-27 (founder): Adminer replaces it
	// once its image exists (TASK-0186), and joins this list then.
	if have["phpmyadmin"] {
		t.Error("phpmyadmin is listed; Adminer replaces it (TASK-0186)")
	}
	for _, n := range []string{"nginx", "php-fpm", "php-cli", "apache", "mariadb", "valkey"} {
		if !have[n] {
			t.Errorf("images.yaml does not list %s (TASK-0012)", n)
		}
	}
}

func TestLoadConfigRefuses(t *testing.T) {
	for name, body := range map[string]string{
		"latest":    "images:\n  - {name: nginx, version: '1', repository: easydigital/nginx, tag: latest}\n",
		"duplicate": "images:\n  - {name: nginx, version: '1', repository: easydigital/nginx, tag: '1'}\n  - {name: nginx, version: '1', repository: easydigital/nginx, tag: '2'}\n",
		"repo":      "images:\n  - {name: nginx, version: '1', repository: nginx, tag: '1'}\n",
		"unknown":   "images:\n  - {name: nginx, version: '1', repository: easydigital/nginx, tag: '1', colour: red}\n",
		"empty":     "images: []\n",
	} {
		if _, err := LoadConfig(writeFile(t, body)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestWaivers(t *testing.T) {
	if _, err := LoadWaivers(writeFile(t, "waivers:\n  - {image: mariadb, id: CVE-1, approved: 2026-10-01, expires: 2026-11-15, reason: x}\n")); err == nil {
		t.Error("a waiver of more than 30 days loaded")
	}
	if _, err := LoadWaivers(writeFile(t, "waivers:\n  - {image: mariadb, id: CVE-1, approved: yes, expires: 2026-10-15, reason: x}\n")); err == nil {
		t.Error("an approval that is not a date loaded")
	}
	if _, err := LoadWaivers(writeFile(t, "waivers:\n  - {image: mariadb, id: CVE-1, approved: 2026-10-01, expires: 2026-10-15, reason: ''}\n")); err == nil {
		t.Error("a waiver with no reason loaded")
	}
	w, err := LoadWaivers(writeFile(t, `waivers:
  - {image: mariadb, id: CVE-A, approved: 2026-10-20, expires: 2026-11-19, reason: not reachable}
  - {image: mariadb, id: CVE-B, approved: proposed, expires: 2026-11-19, reason: not reachable}
  - {image: mariadb, id: CVE-C, approved: 2026-09-20, expires: 2026-10-20, reason: not reachable}
`))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		image, id string
		ok        bool
		why       string
	}{
		{"mariadb", "CVE-A", true, ""},
		{"valkey", "CVE-A", false, ""},
		{"mariadb", "CVE-B", false, "proposed"},
		{"mariadb", "CVE-C", false, "expired"},
		{"mariadb", "CVE-D", false, ""},
	} {
		ok, why := w.Active(c.image, c.id, now)
		if ok != c.ok || !strings.Contains(why, c.why) {
			t.Errorf("%s %s: %v %q", c.image, c.id, ok, why)
		}
	}
}
