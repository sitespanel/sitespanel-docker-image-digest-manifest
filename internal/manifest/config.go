package manifest

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Image is one tracked image version from images.yaml.
type Image struct {
	Name       string   `yaml:"name"`
	Version    string   `yaml:"version"`
	Repository string   `yaml:"repository"` // Docker Hub, for example "easydigital/php" or "library/mariadb"
	Tag        string   `yaml:"tag"`
	FirstParty bool     `yaml:"first_party"`
	Contract   Contract `yaml:"contract"`
}

// Contract is what an image must contain before its digest is approved
// (ADR-0036): the things the SitesPanel stack relies on.
type Contract struct {
	Paths   []string `yaml:"paths"`  // must exist
	Absent  []string `yaml:"absent"` // must not exist
	Outputs []Output `yaml:"outputs"`
	// RecordPHPExtensions stores `php -m` in the manifest, so the panel can
	// list a version's extensions from the image (REQ-0028).
	RecordPHPExtensions bool `yaml:"record_php_extensions"`
}

// Output is a command whose output must contain each listed line or word.
type Output struct {
	Command  string   `yaml:"command"`
	Contains []string `yaml:"contains"`
}

// Config is images.yaml.
type Config struct {
	// Contracts holds shared contracts that images refer to by YAML alias.
	Contracts map[string]Contract `yaml:"contracts"`
	Images    []Image             `yaml:"images"`
}

var (
	nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	repoRE = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*/[a-z0-9]+([._-][a-z0-9]+)*$`)
	tagRE  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

// LoadConfig reads and checks images.yaml.
func LoadConfig(path string) (Config, error) {
	var c Config
	if err := decodeStrict(path, &c); err != nil {
		return Config{}, err
	}
	if len(c.Images) == 0 {
		return Config{}, fmt.Errorf("%s: no images", path)
	}
	seen := map[string]bool{}
	for _, im := range c.Images {
		k := im.Name + " " + im.Version
		switch {
		case !nameRE.MatchString(im.Name):
			return Config{}, fmt.Errorf("%s: name %q", path, im.Name)
		case im.Version == "" || strings.ContainsAny(im.Version, " /"):
			return Config{}, fmt.Errorf("%s: %s: version %q", path, im.Name, im.Version)
		case !repoRE.MatchString(im.Repository):
			return Config{}, fmt.Errorf("%s: %s: repository %q is not namespace/name on Docker Hub", path, k, im.Repository)
		case !tagRE.MatchString(im.Tag) || im.Tag == "latest":
			return Config{}, fmt.Errorf("%s: %s: tag %q (a version tag, never latest)", path, k, im.Tag)
		case seen[k]:
			return Config{}, fmt.Errorf("%s: %s is listed twice", path, k)
		}
		seen[k] = true
	}
	return c, nil
}

// Waiver accepts one finding in one image for at most 30 days (ADR-0036).
type Waiver struct {
	Image string `yaml:"image"` // the images.yaml name; covers every version of it
	ID    string `yaml:"id"`    // CVE or advisory ID
	// Approved is the date the founder approved it, or "proposed", which
	// waives nothing.
	Approved string `yaml:"approved"`
	Expires  string `yaml:"expires"`
	Reason   string `yaml:"reason"`
}

// MaxWaiver is the longest a waiver may last after its approval.
const MaxWaiver = 30 * 24 * time.Hour

// Waivers is security/image-scan-waivers.yaml.
type Waivers struct {
	Waivers []Waiver `yaml:"waivers"`
}

// LoadWaivers reads and checks the waiver file. A malformed line is an
// error: the file is reviewed by hand and must say exactly what it means.
func LoadWaivers(path string) (Waivers, error) {
	var w Waivers
	if err := decodeStrict(path, &w); err != nil {
		return Waivers{}, err
	}
	for i, x := range w.Waivers {
		at := fmt.Sprintf("%s: waiver %d (%s %s)", path, i+1, x.Image, x.ID)
		if !nameRE.MatchString(x.Image) || x.ID == "" || strings.TrimSpace(x.Reason) == "" {
			return Waivers{}, fmt.Errorf("%s: needs image, id and reason", at)
		}
		exp, err := time.Parse(time.DateOnly, x.Expires)
		if err != nil {
			return Waivers{}, fmt.Errorf("%s: expires %q is not YYYY-MM-DD", at, x.Expires)
		}
		if x.Approved == "proposed" {
			continue
		}
		app, err := time.Parse(time.DateOnly, x.Approved)
		if err != nil {
			return Waivers{}, fmt.Errorf("%s: approved %q is not YYYY-MM-DD or proposed", at, x.Approved)
		}
		if exp.Sub(app) > MaxWaiver || exp.Before(app) {
			return Waivers{}, fmt.Errorf("%s: expires more than 30 days after its approval", at)
		}
	}
	return w, nil
}

// Active reports whether a finding in an image is waived on a day, and why
// not when it is not.
func (w Waivers) Active(image, id string, now time.Time) (bool, string) {
	today := now.UTC().Format(time.DateOnly)
	why := ""
	for _, x := range w.Waivers {
		if x.Image != image || x.ID != id {
			continue
		}
		switch {
		case x.Approved == "proposed":
			why = "waiver proposed, not approved"
		case x.Expires < today:
			why = "waiver expired " + x.Expires
		default:
			return true, ""
		}
	}
	return false, why
}

func decodeStrict(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
