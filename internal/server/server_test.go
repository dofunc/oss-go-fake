package server_test

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestS3RequestsAreNotEnabled(t *testing.T) {
	e := startEnv(t, filepath.Join(t.TempDir(), "data"), defaultBuckets)
	for _, r := range []*http.Request{
		mustRequest(t, "GET", e.url+"/bucket/k?X-Amz-Algorithm=AWS4-HMAC-SHA256"),
		withAuth(mustRequest(t, "GET", e.url+"/bucket/k"), "AWS4-HMAC-SHA256 Credential=x"),
		withAuth(mustRequest(t, "GET", e.url+"/bucket/k"), "AWS ak:sig"),
	} {
		if status, _, body := do(t, r); status != http.StatusNotImplemented || !strings.Contains(string(body), "S3 protocol is not enabled") {
			t.Fatalf("%s: %d %s", r.URL, status, body)
		}
	}
}

func TestUnsupportedSubResource(t *testing.T) {
	e := startEnv(t, filepath.Join(t.TempDir(), "data"), defaultBuckets)
	status, code, _ := do(t, mustRequest(t, "GET", e.url+"/bucket/?lifecycle"))
	if status != http.StatusNotImplemented || code != "NotImplemented" {
		t.Fatalf("lifecycle: %d %s", status, code)
	}
}

func TestRequestIDHeader(t *testing.T) {
	e := startEnv(t, filepath.Join(t.TempDir(), "data"), defaultBuckets)
	resp, err := http.Get(e.url + "/bucket/k")
	if err != nil {
		t.Fatal(err)
	}
	closeOrFail(t, resp.Body)
	if id := resp.Header.Get("x-oss-request-id"); len(id) != 24 {
		t.Fatalf("request id = %q", id)
	}
}

func withAuth(r *http.Request, value string) *http.Request {
	r.Header.Set("Authorization", value)
	return r
}
