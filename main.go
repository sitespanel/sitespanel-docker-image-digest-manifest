// Command manifest builds, signs and checks SitesPanel's image digest
// manifest (ADR-0034, ADR-0035, ADR-0036).
//
//	manifest build [-rescan-all] [-trivy "program args"] [-previous URL] -out DIR
//	    read images.yaml and security/image-scan-waivers.yaml, look up each
//	    tag's digest on Docker Hub, scan it and check its contract, and write
//	    DIR/sitespanel-docker-image-digest-manifest.json and its .minisig,
//	    signed with the key in SITESPANEL_IMAGE_MANIFEST_MINISIGN_SECRET_KEY.
//	    Exit 3 when an image has no approved digest (the files are written).
//	manifest verify FILE
//	    check FILE against FILE.minisig and the committed public key
//	manifest keygen PUBFILE
//	    make a manifest key: the public key to PUBFILE, the secret key to
//	    standard output, which must not be a terminal (pipe it into the CI
//	    secret)
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aead.dev/minisign"

	"github.com/sitespanel/sitespanel-docker-image-digest-manifest/internal/manifest"
)

const (
	fileName  = "sitespanel-docker-image-digest-manifest.json"
	pubFile   = "security/image-manifest-minisign.pub"
	keyEnv    = "SITESPANEL_IMAGE_MANIFEST_MINISIGN_SECRET_KEY"
	published = "https://packages.sitespanel.io/images/" + fileName
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "build":
		err = build(os.Args[2:])
	case "verify":
		if len(os.Args) != 3 {
			usage()
		}
		err = verify(os.Args[2])
	case "keygen":
		if len(os.Args) != 3 {
			usage()
		}
		err = keygen(os.Args[2], os.Stdout)
	default:
		usage()
	}
	var exit exitCode
	if errors.As(err, &exit) {
		os.Exit(int(exit))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "manifest:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: manifest build [-rescan-all] [-trivy CMD] [-previous URL] -out DIR | verify FILE | keygen PUBFILE")
	os.Exit(2)
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func build(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	out := fs.String("out", "", "output directory")
	previous := fs.String("previous", published, "URL of the published manifest")
	rescan := fs.Bool("rescan-all", false, "re-scan digests already approved (the daily run)")
	trivy := fs.String("trivy", "trivy", "the Trivy program and its leading arguments")
	docker := fs.String("docker", "docker", "the docker program")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	key, err := secretKey()
	if err != nil {
		return err
	}
	pub, err := minisign.PublicKeyFromFile(pubFile)
	if err != nil {
		return err
	}
	if !pub.Equal(key.Public()) {
		return fmt.Errorf("the secret key in %s does not match %s", keyEnv, pubFile)
	}
	cfg, err := manifest.LoadConfig("images.yaml")
	if err != nil {
		return err
	}
	waivers, err := manifest.LoadWaivers("security/image-scan-waivers.yaml")
	if err != nil {
		return err
	}
	ctx := context.Background()
	prev, err := fetchPrevious(ctx, *previous, pub)
	if err != nil {
		return err
	}
	b := manifest.Builder{
		Config: cfg, Waivers: waivers, Previous: prev,
		Registry: manifest.DockerHub(), Scanner: manifest.Trivy{Command: strings.Fields(*trivy)},
		Runner: manifest.Docker{Program: *docker}, Now: time.Now(), RescanAll: *rescan,
	}
	m, rep, err := b.Build(ctx)
	if err != nil {
		return err
	}
	data, err := m.Encode()
	if err != nil {
		return err
	}
	sig := manifest.Sign(key, m, data)
	if _, err := manifest.Verify(pub, data, sig); err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	path := filepath.Join(*out, fileName)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(path+".minisig", sig, 0o644); err != nil {
		return err
	}
	summary(m, rep)
	if len(rep.Unlisted) > 0 {
		return exitCode(3)
	}
	return nil
}

// fetchPrevious returns nil when nothing is published yet. A published
// manifest that does not verify stops the run: something is wrong.
func fetchPrevious(ctx context.Context, url string, pub minisign.PublicKey) (*manifest.Manifest, error) {
	data, found, err := get(ctx, url)
	if err != nil || !found {
		return nil, err
	}
	sig, found, err := get(ctx, url+".minisig")
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%s has no .minisig", url)
	}
	m, err := manifest.Verify(pub, data, sig)
	if err != nil {
		return nil, fmt.Errorf("the published manifest: %w", err)
	}
	return &m, nil
}

func get(ctx context.Context, url string) ([]byte, bool, error) {
	if path, ok := strings.CutPrefix(url, "file://"); ok {
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return b, err == nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := (&http.Client{Timeout: time.Minute}).Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return b, err == nil, err
	case http.StatusNotFound:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
}

func secretKey() (minisign.PrivateKey, error) {
	var key minisign.PrivateKey
	text := os.Getenv(keyEnv)
	if text == "" {
		return key, fmt.Errorf("%s is not set", keyEnv)
	}
	if err := key.UnmarshalText([]byte(text)); err != nil {
		return key, fmt.Errorf("%s: %w", keyEnv, err)
	}
	return key, nil
}

func summary(m manifest.Manifest, rep manifest.Report) {
	var b strings.Builder
	fmt.Fprintf(&b, "## Image manifest %d\n\n%d images listed, valid until %s.\n\n", m.Sequence, len(m.Images), m.ExpiresAt.Format(time.RFC3339))
	for _, l := range rep.Lines {
		fmt.Fprintf(&b, "- %s\n", l)
	}
	if len(rep.Unlisted) > 0 {
		fmt.Fprintf(&b, "\n**Not listed:** %s\n", strings.Join(rep.Unlisted, ", "))
	}
	fmt.Print(b.String())
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644); err == nil {
			_, _ = f.WriteString(b.String())
			_ = f.Close()
		}
	}
}

func verify(path string) error {
	pub, err := minisign.PublicKeyFromFile(pubFile)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(path + ".minisig")
	if err != nil {
		return err
	}
	m, err := manifest.Verify(pub, data, sig)
	if err != nil {
		return err
	}
	fmt.Printf("manifest %d: %d images, valid until %s\n", m.Sequence, len(m.Images), m.ExpiresAt.Format(time.RFC3339))
	return nil
}

// keygen never shows the secret key: it goes to standard output only when
// that is a pipe or a file.
func keygen(pubPath string, out *os.File) error {
	if st, err := out.Stat(); err != nil || st.Mode()&os.ModeCharDevice != 0 {
		return errors.New("standard output is a terminal; pipe the secret key into the CI secret instead")
	}
	if _, err := os.Stat(pubPath); err == nil {
		return fmt.Errorf("%s exists; a new key goes through the rollover (REQ-0089)", pubPath)
	}
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pubText, err := pub.MarshalText()
	if err != nil {
		return err
	}
	privText, err := priv.MarshalText()
	if err != nil {
		return err
	}
	if err := os.WriteFile(pubPath, append(pubText, '\n'), 0o644); err != nil {
		return err
	}
	_, err = out.Write(privText)
	return err
}
