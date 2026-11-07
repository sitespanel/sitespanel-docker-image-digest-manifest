package manifest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegistriesReadGHCRForGHCRNames (panel TASK-0287, ADR-0067): a repository named ghcr.io/… is read from GitHub's registry, asked for the token service ghcr.io, with
// the prefix removed; anything else is read from Docker Hub as before.
func TestRegistriesReadGHCRForGHCRNames(t *testing.T) {
	var hubSeen, ghcrSeen []string
	serve := func(seen *[]string, service string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/token":
				if got := r.URL.Query().Get("service"); got != service {
					t.Errorf("token service %q, want %q", got, service)
				}
				*seen = append(*seen, r.URL.Query().Get("scope"))
				_, _ = w.Write([]byte(`{"token":"t"}`))
			case r.Method == http.MethodHead:
				w.Header().Set("Docker-Content-Digest", d1)
			default:
				http.NotFound(w, r)
			}
		}))
	}
	hub, gh := serve(&hubSeen, "registry.docker.io"), serve(&ghcrSeen, "ghcr.io")
	defer hub.Close()
	defer gh.Close()
	r := Registries{
		Hub:    &Registry{Client: hub.Client(), AuthURL: hub.URL + "/token", BaseURL: hub.URL, Service: "registry.docker.io", Attempts: 1},
		GitHub: &Registry{Client: gh.Client(), AuthURL: gh.URL + "/token", BaseURL: gh.URL, Service: "ghcr.io", Attempts: 1},
	}
	for _, repo := range []string{"ghcr.io/sitespanel/nginx", "library/mariadb", "docker.io/library/postgres"} {
		if d, err := r.Digest(context.Background(), repo, "1"); err != nil || d != d1 {
			t.Errorf("%s: %q %v", repo, d, err)
		}
	}
	if strings.Join(ghcrSeen, ",") != "repository:sitespanel/nginx:pull" || strings.Join(hubSeen, ",") != "repository:library/mariadb:pull,repository:library/postgres:pull" {
		t.Errorf("scopes asked: ghcr %v, hub %v", ghcrSeen, hubSeen)
	}
}

// TestFirstPartyImagesAreReadFromGHCR: images.yaml may name ghcr.io repositories; a first-party image must be one of sitespanel's there (the old easydigital copies on
// Docker Hub are not read any more); a third-party image stays on Docker Hub; no entry has a mirror when it is already at ghcr.io.
func TestFirstPartyImagesAreReadFromGHCR(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "images.yaml")
		if err := os.WriteFile(p, []byte("images:\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := LoadConfig(write("  - {name: nginx, version: \"1\", repository: ghcr.io/sitespanel/nginx, tag: \"1\", first_party: true}\n  - {name: mariadb, version: \"12\", repository: library/mariadb, tag: 12-noble}\n")); err != nil {
		t.Errorf("ghcr.io first party and Docker Hub third party: %v", err)
	}
	if _, err := LoadConfig(write("  - {name: nginx, version: \"1\", repository: easydigital/nginx, tag: \"1\", first_party: true}\n")); err == nil || !strings.Contains(err.Error(), "ADR-0067") {
		t.Errorf("a first-party image on Docker Hub: %v", err)
	}
	if _, err := LoadConfig(write("  - {name: nginx, version: \"1\", repository: ghcr.io/someoneelse/nginx, tag: \"1\", first_party: true}\n")); err == nil {
		t.Error("a first-party image of another organisation was accepted")
	}
	if got := MirrorOf("ghcr.io/sitespanel/php"); got != "" {
		t.Errorf("an image at ghcr.io has a mirror: %q", got)
	}
	if got := MirrorOf("docker.io/library/mariadb"); got != MirrorPrefix+"library-mariadb" {
		t.Errorf("a Docker Hub image's mirror: %q", got)
	}
	if QualifiedRepository("ghcr.io/sitespanel/php") != "ghcr.io/sitespanel/php" || QualifiedRepository("library/mariadb") != "docker.io/library/mariadb" {
		t.Error("QualifiedRepository")
	}
}

func TestAttestationCommand(t *testing.T) {
	g := GHAttestation{Owner: "sitespanel"}
	args, err := g.Args("ghcr.io/sitespanel/php", d1)
	if err != nil {
		t.Fatal(err)
	}
	want := "attestation verify oci://ghcr.io/sitespanel/php@" + d1 + " --repo sitespanel/php-docker --signer-workflow sitespanel/php-docker/.github/workflows/image.yml --source-ref refs/heads/main"
	if strings.Join(args, " ") != want {
		t.Errorf("\n got %s\nwant %s", strings.Join(args, " "), want)
	}
	for _, bad := range [][2]string{{"docker.io/library/mariadb", d1}, {"ghcr.io/other/php", d1}, {"ghcr.io/sitespanel/php", "latest"}, {"ghcr.io/sitespanel/a/b", d1}} {
		if _, err := g.Args(bad[0], bad[1]); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}

type fakeAttester struct {
	err    error
	called []string
}

func (f *fakeAttester) Verify(_ context.Context, repo, digest string) error {
	f.called = append(f.called, repo+"@"+digest)
	return f.err
}

// TestBuildNeedsTheAttestationOfAFirstPartyImage (ADR-0067, ADR-0035): a first-party digest with no valid build attestation is not approved and not even scanned; one
// with it is approved without a mirror; a third-party image is not asked.
func TestBuildNeedsTheAttestationOfAFirstPartyImage(t *testing.T) {
	php := phpImage()
	php.Repository = "ghcr.io/sitespanel/php"
	b, sc, _ := builder(php, mariadbImage())
	b.Registry = fakeRegistry{"ghcr.io/sitespanel/php:8.4-fpm-trixie": d1, "library/mariadb:11.8-noble": d1}
	att := &fakeAttester{}
	b.Attester = att
	m, rep, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, ok := m.Find("php-fpm", "8.4")
	if !ok || got.Ref() != "ghcr.io/sitespanel/php@"+d1 || got.Mirror != "" {
		t.Errorf("the first-party entry: %+v listed %v", got, ok)
	}
	if maria, _ := m.Find("mariadb", "11.8"); maria.Mirror == "" {
		t.Error("the third-party image lost its mirror")
	}
	if len(att.called) != 1 || att.called[0] != "ghcr.io/sitespanel/php@"+d1 {
		t.Errorf("the attestation was asked for %v", att.called)
	}

	b2, sc2, _ := builder(php)
	b2.Registry = fakeRegistry{"ghcr.io/sitespanel/php:8.4-fpm-trixie": d1}
	b2.Attester = &fakeAttester{err: errors.New("no matching attestation")}
	m2, rep2, err := b2.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(m2.Images) != 0 || len(sc2.scanned) != 0 || len(rep2.Unlisted) != 1 || !strings.Contains(strings.Join(rep2.Lines, "\n"), "build attestation") {
		t.Errorf("an unattested digest: images %v, scanned %v, unlisted %v, report %v", m2.Images, sc2.scanned, rep2.Unlisted, rep2.Lines)
	}
	_, _ = sc, rep
}
