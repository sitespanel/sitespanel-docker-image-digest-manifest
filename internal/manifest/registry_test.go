package manifest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegistryDigestRetriesRateLimits(t *testing.T) {
	heads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			if r.URL.Query().Get("scope") != "repository:easydigital/nginx:pull" {
				t.Errorf("scope %q", r.URL.Query().Get("scope"))
			}
			_, _ = w.Write([]byte(`{"token":"t"}`))
		case r.Method == http.MethodHead && r.URL.Path == "/v2/easydigital/nginx/manifests/1.30.5":
			heads++
			if r.Header.Get("Authorization") != "Bearer t" || !strings.Contains(r.Header.Get("Accept"), "image.index") {
				t.Errorf("headers %v", r.Header)
			}
			if heads < 3 {
				w.Header().Set("Retry-After", "7")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.Header().Set("Docker-Content-Digest", d1)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	var waits []time.Duration
	r := &Registry{Client: srv.Client(), AuthURL: srv.URL + "/token", BaseURL: srv.URL, Attempts: 6,
		Sleep: func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }}
	d, err := r.Digest(context.Background(), "easydigital/nginx", "1.30.5")
	if err != nil || d != d1 {
		t.Fatalf("%q %v", d, err)
	}
	if len(waits) != 2 || waits[0] != 7*time.Second {
		t.Fatalf("waits %v", waits)
	}

	// A missing tag is not retried.
	waits = nil
	if _, err := r.Digest(context.Background(), "easydigital/nginx", "9.9.9"); err == nil || len(waits) != 0 {
		t.Fatalf("missing tag: %v, waits %v", err, waits)
	}
}
