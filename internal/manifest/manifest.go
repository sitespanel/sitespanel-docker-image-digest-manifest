// Package manifest builds, signs and verifies SitesPanel's image digest
// manifest: the list of image digests customer servers may run (ADR-0034,
// ADR-0035, ADR-0036). Servers accept only digests listed in a manifest
// whose signature verifies with the manifest key.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"aead.dev/minisign"
)

// Schema is the manifest format version. A server refuses a schema it does
// not know.
const Schema = 1

// Validity is how long a manifest is accepted after it is generated. The
// workflow publishes every 6 hours, so this leaves room for days of CI
// outage before servers stop taking new images.
const Validity = 14 * 24 * time.Hour

// Manifest is the published document.
type Manifest struct {
	Schema int `json:"schema"`
	// Sequence only grows; a server refuses a manifest older than the one it
	// already holds, so an old manifest cannot be replayed.
	Sequence    int64     `json:"sequence"`
	GeneratedAt time.Time `json:"generated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Images      []Entry   `json:"images"`
}

// Entry is one approved image version.
type Entry struct {
	Name       string `json:"name"`       // what servers ask for, for example "php-fpm"
	Version    string `json:"version"`    // for example "8.4"
	Repository string `json:"repository"` // for example "docker.io/easydigital/php"
	Tag        string `json:"tag"`        // informational: the digest decides
	Digest     string `json:"digest"`
	// Mirror is the same image, copied unchanged by digest, in SitesPanel's own
	// organisation at ghcr.io: servers fall back to it when the primary
	// registry fails (ADR-0035, REQ-0068).
	Mirror    string    `json:"mirror,omitempty"`
	ScannedAt time.Time `json:"scanned_at"`
	// Waived lists the findings accepted by a founder-approved waiver.
	Waived []string `json:"waived,omitempty"`
	// Findings lists unwaived fixable high or critical findings that a later
	// re-scan found in this still-listed digest; the panel alerts staff.
	Findings      []string `json:"findings,omitempty"`
	PHPExtensions []string `json:"php_extensions,omitempty"`
	// SBOM names the software bill of materials of this digest, published next to the manifest (TASK-0117).
	SBOM *SBOMRef `json:"sbom,omitempty"`
	// SupportEnds is the publisher's security-support end for this version, from images.yaml (informational).
	SupportEnds string `json:"support_ends,omitempty"`
}

// SBOMRef points at an SPDX document made from the approved digest.
type SBOMRef struct {
	Format string `json:"format"` // spdx-json
	Path   string `json:"path"`   // relative to the manifest's folder, for example sbom/nginx-1.30.5-0123456789ab.spdx.json
	SHA256 string `json:"sha256"` // of the document's bytes
}

var (
	sbomPathRE = regexp.MustCompile(`^sbom/[a-z0-9][a-z0-9.-]{0,80}\.spdx\.json$`)
	sbomShaRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// MirrorPrefix is where the mirror copies live.
const MirrorPrefix = "ghcr.io/sitespanel/sitespanel-mirror-"

// MirrorOf is the mirror repository of a primary one: the path with its slashes
// as dashes, so docker.io/easydigital/php is ghcr.io/sitespanel/sitespanel-mirror-easydigital-php.
func MirrorOf(repository string) string {
	path := strings.TrimPrefix(repository, "docker.io/")
	return MirrorPrefix + strings.ReplaceAll(path, "/", "-")
}

// Ref is the pull reference, by digest.
func (e Entry) Ref() string { return e.Repository + "@" + e.Digest }

// Find returns the entry for a name and version.
func (m *Manifest) Find(name, version string) (Entry, bool) {
	if m == nil {
		return Entry{}, false
	}
	for _, e := range m.Images {
		if e.Name == name && e.Version == version {
			return e, true
		}
	}
	return Entry{}, false
}

// Encode is the exact byte form that is signed and published.
func (m Manifest) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Decode parses a manifest and checks its shape.
func Decode(data []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	if m.Schema != Schema {
		return Manifest{}, fmt.Errorf("manifest: schema %d is not %d", m.Schema, Schema)
	}
	seen := map[string]bool{}
	for _, e := range m.Images {
		if e.Name == "" || e.Version == "" || e.Repository == "" {
			return Manifest{}, errors.New("manifest: an entry has no name, version or repository")
		}
		if e.SBOM != nil && (e.SBOM.Format != "spdx-json" || !sbomPathRE.MatchString(e.SBOM.Path) || !sbomShaRE.MatchString(e.SBOM.SHA256)) {
			return Manifest{}, fmt.Errorf("manifest: %s %s: the SBOM reference is not valid", e.Name, e.Version)
		}
		if e.Mirror != "" && !strings.HasPrefix(e.Mirror, MirrorPrefix) {
			return Manifest{}, fmt.Errorf("manifest: %s %s: mirror %q is not in the SitesPanel organisation", e.Name, e.Version, e.Mirror)
		}
		if !validDigest(e.Digest) {
			return Manifest{}, fmt.Errorf("manifest: %s %s: digest %q is not sha256", e.Name, e.Version, e.Digest)
		}
		k := e.Name + " " + e.Version
		if seen[k] {
			return Manifest{}, fmt.Errorf("manifest: %s is listed twice", k)
		}
		seen[k] = true
	}
	return m, nil
}

func validDigest(d string) bool {
	h, ok := strings.CutPrefix(d, "sha256:")
	if !ok || len(h) != 64 {
		return false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// trustedComment is signed with the manifest, so the sequence cannot be
// changed without the key.
func trustedComment(m Manifest) string {
	return fmt.Sprintf("sitespanel-docker-image-digest-manifest schema=%d sequence=%d", m.Schema, m.Sequence)
}

// Sign returns the minisign signature of the encoded manifest.
func Sign(key minisign.PrivateKey, m Manifest, data []byte) []byte {
	return minisign.SignWithComments(key, data, trustedComment(m), "signature from the SitesPanel image manifest key")
}

// Verify checks data against its signature and the public key, decodes it,
// and checks that the signed sequence matches the document.
func Verify(pub minisign.PublicKey, data, sig []byte) (Manifest, error) {
	if !minisign.Verify(pub, data, sig) {
		return Manifest{}, errors.New("manifest: the signature does not verify with the manifest key")
	}
	m, err := Decode(data)
	if err != nil {
		return Manifest{}, err
	}
	var s minisign.Signature
	if err := s.UnmarshalText(sig); err != nil {
		return Manifest{}, fmt.Errorf("manifest: %w", err)
	}
	if s.TrustedComment != trustedComment(m) {
		return Manifest{}, errors.New("manifest: the signed sequence does not match the document")
	}
	return m, nil
}
