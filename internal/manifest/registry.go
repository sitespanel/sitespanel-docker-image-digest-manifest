package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Registry reads the current digest of a tag on Docker Hub, read only and
// anonymously. HEAD requests do not count against Docker Hub's pull limit,
// but Docker Hub answers 429 when asked too fast, so a lookup waits and
// retries.
type Registry struct {
	Client   *http.Client
	AuthURL  string // https://auth.docker.io/token
	BaseURL  string // https://registry-1.docker.io
	Attempts int
	Sleep    func(context.Context, time.Duration) error
}

// DockerHub is the production registry.
func DockerHub() *Registry {
	return &Registry{
		Client:   &http.Client{Timeout: 30 * time.Second},
		AuthURL:  "https://auth.docker.io/token",
		BaseURL:  "https://registry-1.docker.io",
		Attempts: 6,
		Sleep:    sleep,
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// accept lists every manifest type, so a multi-platform tag answers with
// its index digest, the one `docker pull repo@digest` resolves.
const accept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"

// Digest returns the digest a tag points at now.
func (r *Registry) Digest(ctx context.Context, repository, tag string) (string, error) {
	var last error
	for try := 1; try <= r.Attempts; try++ {
		d, wait, err := r.digestOnce(ctx, repository, tag)
		if err == nil {
			return d, nil
		}
		last = err
		if wait == 0 || try == r.Attempts {
			break
		}
		if err := r.Sleep(ctx, wait); err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("digest of %s:%s: %w", repository, tag, last)
}

// digestOnce returns a wait above zero when the error is worth a retry.
func (r *Registry) digestOnce(ctx context.Context, repository, tag string) (string, time.Duration, error) {
	tok, wait, err := r.token(ctx, repository)
	if err != nil {
		return "", wait, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, r.BaseURL+"/v2/"+repository+"/manifests/"+url.PathEscape(tag), nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", accept)
	resp, err := r.Client.Do(req)
	if err != nil {
		return "", 5 * time.Second, err
	}
	resp.Body.Close()
	if wait, retry := retryable(resp); retry {
		return "", wait, fmt.Errorf("registry answered %s", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("registry answered %s", resp.Status)
	}
	d := resp.Header.Get("Docker-Content-Digest")
	if !validDigest(d) {
		return "", 0, fmt.Errorf("registry gave digest %q", d)
	}
	return d, 0, nil
}

func (r *Registry) token(ctx context.Context, repository string) (string, time.Duration, error) {
	q := url.Values{"service": {"registry.docker.io"}, "scope": {"repository:" + repository + ":pull"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.AuthURL+"?"+q.Encode(), nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return "", 5 * time.Second, err
	}
	defer resp.Body.Close()
	if wait, retry := retryable(resp); retry {
		return "", wait, fmt.Errorf("token service answered %s", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("token service answered %s", resp.Status)
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body.Token == "" {
		return "", 0, fmt.Errorf("token service gave no token")
	}
	return body.Token, 0, nil
}

// retryable says whether a response is a rate limit or a passing server
// error, and how long to wait (Retry-After when given, at most 2 minutes).
func retryable(resp *http.Response) (time.Duration, bool) {
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
		return 0, false
	}
	wait := 20 * time.Second
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		wait = time.Duration(s) * time.Second
	}
	return min(wait, 2*time.Minute), true
}
