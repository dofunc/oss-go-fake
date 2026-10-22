package oss

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dofunc/oss-go-fake/internal/service"
	"github.com/dofunc/oss-go-fake/internal/storage"
)

func TestParseRange(t *testing.T) {
	r := func(start, end int64) *storage.ByteRange { return &storage.ByteRange{Start: start, End: end} }
	cases := []struct {
		header   string
		standard bool
		want     *storage.ByteRange
		err      bool
	}{
		{"bytes=0-", false, r(0, 9), false},
		{"bytes=-5", false, r(5, 9), false},
		{"bytes=2-4", false, r(2, 4), false},
		{"bytes=5-2", false, nil, false},
		{"bytes=5-2", true, nil, false},
		{"bytes=999-", false, nil, false},
		{"bytes=999-", true, nil, true},
		{"bytes=5-999", false, nil, false},
		{"bytes=5-999", true, r(5, 9), false},
		{"bytes=-999", false, nil, false},
		{"bytes=-999", true, r(0, 9), false},
		{"bytes=0-1,3-4", false, nil, false},
		{"bytes=0-1,3-4", true, nil, false},
		{"items=0-1", false, nil, false},
		{"", false, nil, false},
	}
	for _, c := range cases {
		got, err := parseRange(c.header, 10, c.standard)
		if (err != nil) != c.err {
			t.Errorf("%q standard=%v: err = %v", c.header, c.standard, err)
			continue
		}
		if c.err && service.KindOf(err) != service.KindInvalidRange {
			t.Errorf("%q: err kind = %d", c.header, service.KindOf(err))
		}
		if (got == nil) != (c.want == nil) || got != nil && *got != *c.want {
			t.Errorf("%q standard=%v: range = %+v, want %+v", c.header, c.standard, got, c.want)
		}
	}
}

func TestParseAddress(t *testing.T) {
	cases := []struct {
		host, path, domain, bucket, key string
	}{
		{"attachments.oss.fake.local:8080", "/a/b.jpg", "oss.fake.local", "attachments", "a/b.jpg"},
		{"oss.fake.local:8080", "/attachments/a/b.jpg", "oss.fake.local", "attachments", "a/b.jpg"},
		{"192.0.2.10:28300", "/attachments/a/b.jpg", "", "attachments", "a/b.jpg"},
		{"attachments.oss.fake.local", "/x/a", "", "x", "a"},
		{"127.0.0.1", "/", "", "", ""},
		{"127.0.0.1", "/attachments/", "", "attachments", ""},
		{"127.0.0.1", "/attachments", "", "attachments", ""},
		{"127.0.0.1", "/b/a//c", "", "b", "a//c"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", c.path, nil)
		r.Host = c.host
		bucket, key := parseAddress(r, c.domain)
		if bucket != c.bucket || key != c.key {
			t.Errorf("%s%s domain %q: (%q, %q), want (%q, %q)", c.host, c.path, c.domain, bucket, key, c.bucket, c.key)
		}
	}
}

func errorResponse(t *testing.T, method string) (*httptest.ResponseRecorder, errorXML) {
	t.Helper()
	w := httptest.NewRecorder()
	w.Header().Set(headerRequestID, "0123456789abcdef01234567")
	writeError(w, httptest.NewRequest(method, "/b/k", nil), &service.Error{Kind: service.KindNoSuchKey, Message: "missing"})
	raw, err := base64.StdEncoding.DecodeString(w.Header().Get("x-oss-err"))
	if err != nil {
		t.Fatal(err)
	}
	var e errorXML
	if err := xml.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	return w, e
}

func TestErrorXML(t *testing.T) {
	w, e := errorResponse(t, "GET")
	if w.Code != http.StatusNotFound || e.Code != "NoSuchKey" || e.Message != "missing" || e.HostID == "" || e.EC != ecUnmapped {
		t.Fatalf("status %d, error %+v", w.Code, e)
	}
	if e.RequestID != w.Header().Get(headerRequestID) {
		t.Fatalf("RequestId %q differs from header %q", e.RequestID, w.Header().Get(headerRequestID))
	}
	if w.Header().Get("x-oss-ec") != ecUnmapped {
		t.Fatalf("x-oss-ec = %q", w.Header().Get("x-oss-ec"))
	}
	raw, _ := base64.StdEncoding.DecodeString(w.Header().Get("x-oss-err"))
	if !bytes.Equal(raw, w.Body.Bytes()) {
		t.Fatal("x-oss-err differs from the body")
	}
}

func TestHeadErrorHasNoBody(t *testing.T) {
	head, headErr := errorResponse(t, "HEAD")
	_, getErr := errorResponse(t, "GET")
	if head.Body.Len() != 0 {
		t.Fatalf("HEAD error carries %d body bytes", head.Body.Len())
	}
	if headErr != getErr {
		t.Fatalf("HEAD x-oss-err %+v differs from GET %+v", headErr, getErr)
	}
}
