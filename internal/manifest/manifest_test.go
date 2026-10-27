package manifest

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"aead.dev/minisign"
)

func testKey(t *testing.T) (minisign.PublicKey, minisign.PrivateKey) {
	t.Helper()
	pub, priv, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

const d1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
const d2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

func sample() Manifest {
	at := time.Date(2026, 10, 27, 6, 0, 0, 0, time.UTC)
	return Manifest{Schema: Schema, Sequence: at.Unix(), GeneratedAt: at, ExpiresAt: at.Add(Validity), Images: []Entry{
		{Name: "nginx", Version: "1.30.5", Repository: "docker.io/easydigital/nginx", Tag: "1.30.5", Digest: d1, ScannedAt: at},
	}}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv := testKey(t)
	m := sample()
	data, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	sig := Sign(priv, m, data)
	got, err := Verify(pub, data, sig)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != m.Sequence || got.Images[0].Ref() != "docker.io/easydigital/nginx@"+d1 {
		t.Fatalf("round trip: %+v", got)
	}

	tampered := []byte(strings.Replace(string(data), d1, d2, 1))
	if _, err := Verify(pub, tampered, sig); err == nil {
		t.Fatal("a changed digest verified")
	}
	other, _ := testKey(t)
	if _, err := Verify(other, data, sig); err == nil {
		t.Fatal("another key verified")
	}
	// A signature whose signed sequence differs from the document's (for
	// example an older signature replayed with a document edited to look
	// newer) is refused even though the key is right.
	older := m
	older.Sequence--
	if _, err := Verify(pub, data, Sign(priv, older, data)); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("sequence mismatch: %v", err)
	}
}

func TestDecodeRefusesBadDocuments(t *testing.T) {
	for name, doc := range map[string]string{
		"schema":    `{"schema":2,"sequence":1,"generated_at":"2026-10-27T00:00:00Z","expires_at":"2026-10-28T00:00:00Z","images":[]}`,
		"unknown":   `{"schema":1,"sequence":1,"generated_at":"2026-10-27T00:00:00Z","expires_at":"2026-10-28T00:00:00Z","images":[],"extra":1}`,
		"digest":    `{"schema":1,"sequence":1,"generated_at":"2026-10-27T00:00:00Z","expires_at":"2026-10-28T00:00:00Z","images":[{"name":"nginx","version":"1","repository":"docker.io/a/b","tag":"1","digest":"sha256:abc","scanned_at":"2026-10-27T00:00:00Z"}]}`,
		"duplicate": `{"schema":1,"sequence":1,"generated_at":"2026-10-27T00:00:00Z","expires_at":"2026-10-28T00:00:00Z","images":[{"name":"nginx","version":"1","repository":"docker.io/a/b","tag":"1","digest":"` + d1 + `","scanned_at":"2026-10-27T00:00:00Z"},{"name":"nginx","version":"1","repository":"docker.io/a/b","tag":"1","digest":"` + d2 + `","scanned_at":"2026-10-27T00:00:00Z"}]}`,
	} {
		if _, err := Decode([]byte(doc)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}
