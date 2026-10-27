package manifest

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Scanner finds fixable high and critical vulnerabilities in an image.
type Scanner interface {
	Scan(ctx context.Context, ref string) ([]Finding, error)
}

// Digester reads the digest a tag points at.
type Digester interface {
	Digest(ctx context.Context, repository, tag string) (string, error)
}

// Builder makes a new manifest from images.yaml, the waivers and the
// manifest published before.
type Builder struct {
	Config   Config
	Waivers  Waivers
	Previous *Manifest // nil on the first run
	Registry Digester
	Scanner  Scanner
	Runner   Runner
	Now      time.Time
	// RescanAll re-scans digests already approved (the daily run); other
	// runs check only digests that changed.
	RescanAll bool
}

// Report says what a run did, for the job summary.
type Report struct {
	Lines []string
	// Unlisted names images that have no approved digest at all; the
	// workflow fails so the founder hears about it.
	Unlisted []string
	seen     map[string]bool // "image ID" of every finding scanned this run
}

func (r *Report) addf(format string, args ...any) {
	r.Lines = append(r.Lines, fmt.Sprintf(format, args...))
}

// verdict is the outcome of checking one digest.
type verdict struct {
	findings []string // unwaived finding IDs
	problems []string // every reason it cannot be approved, readable
}

// Build returns the new manifest. Errors talking to the registry, the
// scanner or docker stop the run, so nothing half-checked is published.
func (b Builder) Build(ctx context.Context) (Manifest, Report, error) {
	now := b.Now.UTC().Truncate(time.Second)
	m := Manifest{Schema: Schema, Sequence: now.Unix(), GeneratedAt: now, ExpiresAt: now.Add(Validity)}
	if b.Previous != nil && m.Sequence <= b.Previous.Sequence {
		m.Sequence = b.Previous.Sequence + 1
	}
	rep := Report{seen: map[string]bool{}}
	for _, im := range b.Config.Images {
		e, listed, err := b.one(ctx, im, now, &rep)
		if err != nil {
			return Manifest{}, Report{}, fmt.Errorf("%s %s: %w", im.Name, im.Version, err)
		}
		if listed {
			m.Images = append(m.Images, e)
		} else {
			rep.Unlisted = append(rep.Unlisted, im.Name+" "+im.Version)
		}
	}
	b.reportWaivers(&rep, now)
	return m, rep, nil
}

func (b Builder) one(ctx context.Context, im Image, now time.Time, rep *Report) (Entry, bool, error) {
	repo := "docker.io/" + im.Repository
	digest, err := b.Registry.Digest(ctx, im.Repository, im.Tag)
	if err != nil {
		return Entry{}, false, err
	}
	prev, hadPrev := b.Previous.Find(im.Name, im.Version)
	if hadPrev && prev.Repository != repo {
		hadPrev = false // the image moved: the old approval does not carry over
	}
	if hadPrev && prev.Digest == digest && !b.RescanAll {
		rep.addf("%s %s: unchanged %s", im.Name, im.Version, short(digest))
		return prev, true, nil
	}
	cand := Entry{Name: im.Name, Version: im.Version, Repository: repo, Tag: im.Tag, Digest: digest, ScannedAt: now}
	v, err := b.check(ctx, im, &cand, now, rep)
	if err != nil {
		return Entry{}, false, err
	}
	why := strings.Join(v.problems, "; ")
	switch {
	case len(v.problems) == 0 && hadPrev && prev.Digest != digest:
		rep.addf("%s %s: approved %s (was %s)", im.Name, im.Version, short(digest), short(prev.Digest))
		return cand, true, nil
	case len(v.problems) == 0:
		rep.addf("%s %s: approved %s", im.Name, im.Version, short(digest))
		return cand, true, nil
	case hadPrev && prev.Digest == digest:
		// The daily re-scan found something new in a listed digest. It stays
		// listed, since servers run it, and its findings make the panel
		// alert staff (TEST-416).
		cand.Findings = v.findings
		rep.addf("%s %s: still listed, the re-scan found: %s", im.Name, im.Version, why)
		return cand, true, nil
	case hadPrev && b.RescanAll:
		rep.addf("%s %s: kept %s; new digest %s not approved: %s", im.Name, im.Version, short(prev.Digest), short(digest), why)
		again := Entry{Name: prev.Name, Version: prev.Version, Repository: prev.Repository, Tag: prev.Tag, Digest: prev.Digest, ScannedAt: now, PHPExtensions: prev.PHPExtensions}
		old, err := b.scan(ctx, im, &again, now, rep)
		if err != nil {
			return Entry{}, false, err
		}
		again.Findings = old.findings
		return again, true, nil
	case hadPrev:
		rep.addf("%s %s: kept %s; new digest %s not approved: %s", im.Name, im.Version, short(prev.Digest), short(digest), why)
		return prev, true, nil
	default:
		rep.addf("%s %s: NOT LISTED, %s not approved: %s", im.Name, im.Version, short(digest), why)
		return Entry{}, false, nil
	}
}

// check scans the digest and checks the image contract.
func (b Builder) check(ctx context.Context, im Image, e *Entry, now time.Time, rep *Report) (verdict, error) {
	v, err := b.scan(ctx, im, e, now, rep)
	if err != nil {
		return verdict{}, err
	}
	c := im.Contract
	if len(c.Paths)+len(c.Absent)+len(c.Outputs) == 0 && !c.RecordPHPExtensions {
		return v, nil
	}
	lacks, exts, err := checkContract(ctx, b.Runner, e.Ref(), c)
	b.Runner.Remove(ctx, e.Ref())
	if err != nil {
		return verdict{}, err
	}
	for _, l := range lacks {
		v.problems = append(v.problems, "contract: "+l)
	}
	e.PHPExtensions = exts
	return v, nil
}

// scan fills Waived and returns the unwaived findings.
func (b Builder) scan(ctx context.Context, im Image, e *Entry, now time.Time, rep *Report) (verdict, error) {
	findings, err := b.Scanner.Scan(ctx, e.Ref())
	if err != nil {
		return verdict{}, err
	}
	var v verdict
	for _, f := range findings {
		rep.seen[im.Name+" "+f.ID] = true
		ok, why := b.Waivers.Active(im.Name, f.ID, now)
		if ok {
			e.Waived = append(e.Waived, f.ID)
			continue
		}
		if why == "" {
			why = "no waiver"
		}
		v.findings = append(v.findings, f.ID)
		v.problems = append(v.problems, fmt.Sprintf("%s %s in %s %s, fixed in %s (%s)", f.Severity, f.ID, f.Package, f.Installed, f.Fixed, why))
	}
	return v, nil
}

// reportWaivers names waivers that are only proposed or have expired, and,
// after a full re-scan, those whose finding no scan saw (stale: delete them).
func (b Builder) reportWaivers(rep *Report, now time.Time) {
	today := now.Format(time.DateOnly)
	for _, w := range b.Waivers.Waivers {
		switch {
		case b.RescanAll && !rep.seen[w.Image+" "+w.ID]:
			rep.addf("waiver %s %s: stale, no scan found it; delete the line", w.Image, w.ID)
		case w.Approved == "proposed":
			rep.addf("waiver %s %s: proposed, waits for the founder's approval", w.Image, w.ID)
		case w.Expires < today:
			rep.addf("waiver %s %s: expired %s; renew it with the founder or re-pin", w.Image, w.ID, w.Expires)
		}
	}
	sort.Strings(rep.Unlisted)
}

func short(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}
