package manifest

import (
	"context"
	"fmt"
	"os/exec"
	"path"
	"strings"
)

// Attester checks that a digest was built by its image repository's own workflow on main (panel ADR-0067, ADR-0035): the signed build-provenance attestation the
// image workflow attaches. A first-party image without one is not approved.
type Attester interface {
	Verify(ctx context.Context, repository, digest string) error
}

// GHAttestation checks with `gh attestation verify` (GitHub CLI), which reads the attestation from GitHub and verifies its signature against the Sigstore public-good
// root. It needs GH_TOKEN in the environment; the image is public, so the token needs no scope.
type GHAttestation struct {
	Program string // gh
	// Owner is the organisation whose image repositories are trusted (sitespanel).
	Owner string
}

// SourceOf is the image repository a first-party image at ghcr.io is built in and the workflow that publishes it: ghcr.io/sitespanel/php is built by
// sitespanel/php-docker, in .github/workflows/image.yml.
func SourceOf(repository string) (repo, workflow string, err error) {
	rest, ok := strings.CutPrefix(repository, GHCR)
	if !ok {
		return "", "", fmt.Errorf("%s is not at %s", repository, GHCR)
	}
	owner, name, ok := strings.Cut(rest, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("%s is not %sowner/name", repository, GHCR)
	}
	repo = owner + "/" + name + "-docker"
	return repo, path.Join(repo, ".github/workflows/image.yml"), nil
}

// Args are the arguments of the check for one digest.
func (g GHAttestation) Args(repository, digest string) ([]string, error) {
	if !validDigest(digest) {
		return nil, fmt.Errorf("digest %q", digest)
	}
	repo, workflow, err := SourceOf(repository)
	if err != nil {
		return nil, err
	}
	if g.Owner != "" && !strings.HasPrefix(repo, g.Owner+"/") {
		return nil, fmt.Errorf("%s is not an image repository of %s", repo, g.Owner)
	}
	return []string{"attestation", "verify", "oci://" + repository + "@" + digest, "--repo", repo, "--signer-workflow", workflow, "--source-ref", "refs/heads/main"}, nil
}

// Verify runs the check.
func (g GHAttestation) Verify(ctx context.Context, repository, digest string) error {
	args, err := g.Args(repository, digest)
	if err != nil {
		return err
	}
	prog := g.Program
	if prog == "" {
		prog = "gh"
	}
	if out, err := exec.CommandContext(ctx, prog, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %s", strings.Join(args[2:3], ""), strings.TrimSpace(tail(string(out), 400)))
	}
	return nil
}
