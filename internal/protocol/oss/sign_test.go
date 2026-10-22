package oss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/signer"
)

func ptr(s string) *string { return &s }

// serverSide replays a signed client request as the server receives it, path-style.
func serverSide(client *http.Request, bucket, key string) *http.Request {
	target := "/" + bucket + "/" + uriEncode(key, false)
	if client.URL.RawQuery != "" {
		target += "?" + client.URL.RawQuery
	}
	r := httptest.NewRequest(client.Method, target, nil)
	r.Header = client.Header.Clone()
	return r
}

func credentialsOf(t *testing.T) *credentials.Credentials {
	t.Helper()
	cred, err := credentials.NewStaticCredentialsProvider("ak", "sk").GetCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return &cred
}

// sdkVectorQuery is the query string of the SDK's own V4 signer tests.
func sdkVectorQuery() string {
	values := url.Values{}
	values.Add("param1", "value1")
	values.Add("+param1", "value3")
	values.Add("|param1", "value4")
	values.Add("+param2", "")
	values.Add("|param2", "")
	values.Add("param2", "")
	return values.Encode()
}

func sdkVectorHeaders() http.Header {
	h := http.Header{}
	h.Add("x-oss-head1", "value")
	h.Add("abc", "value")
	h.Add("ZAbc", "value")
	h.Add("XYZ", "value")
	h.Add("content-type", "text/plain")
	h.Add("x-oss-content-sha256", "UNSIGNED-PAYLOAD")
	return h
}

// TestV4MatchesSDKVector signs the SDK's published V4 vectors and checks that the server builds
// the very same string to sign and accepts the signature the SDK tests pin down.
func TestV4MatchesSDKVector(t *testing.T) {
	cases := []struct {
		name       string
		signedAt   int64
		additional []string
		wantAuth   string
	}{
		{"plain", 1702743657, nil,
			"OSS4-HMAC-SHA256 Credential=ak/20231216/cn-hangzhou/oss/aliyun_v4_request,Signature=e21d18daa82167720f9b1047ae7e7f1ce7cb77a31e8203a7d5f4624fa0284afe"},
		{"additional headers", 1702747512, []string{"ZAbc", "abc"},
			"OSS4-HMAC-SHA256 Credential=ak/20231216/cn-hangzhou/oss/aliyun_v4_request,AdditionalHeaders=abc;zabc,Signature=4a4183c187c07c8947db7620deb0a6b38d9fbdd34187b6dbaccb316fa251212f"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, _ := http.NewRequest("PUT", "http://bucket.oss-cn-hangzhou.aliyuncs.com", nil)
			client.Header = sdkVectorHeaders()
			client.URL.RawQuery = sdkVectorQuery()
			signedAt := time.Unix(c.signedAt, 0).UTC()
			ctx := &signer.SigningContext{
				Bucket: ptr("bucket"), Key: ptr("1234+-/123/1.txt"), Request: client,
				Credentials: credentialsOf(t), Product: ptr("oss"), Region: ptr("cn-hangzhou"),
				Time: signedAt, AdditionalHeaders: c.additional,
			}
			if err := (&signer.SignerV4{}).Sign(context.Background(), ctx); err != nil {
				t.Fatal(err)
			}
			if got := client.Header.Get("Authorization"); got != c.wantAuth {
				t.Fatalf("SDK signed %s, vector says %s", got, c.wantAuth)
			}

			r := serverSide(client, "bucket", "1234+-/123/1.txt")
			fields := parseV4Authorization(strings.TrimPrefix(r.Header.Get("Authorization"), v4Algorithm+" "))
			var additional []string
			if fields["AdditionalHeaders"] != "" {
				additional = strings.Split(fields["AdditionalHeaders"], ";")
			}
			got := stringToSignV4(r.Header.Get("x-oss-date"), "20231216/cn-hangzhou/oss/aliyun_v4_request",
				canonicalRequestV4(r, "bucket", "1234+-/123/1.txt", additional, false))
			if got != ctx.StringToSign {
				t.Fatalf("string to sign differs\nserver: %q\nsdk:    %q", got, ctx.StringToSign)
			}
			a := NewAuthenticator(map[string]string{"ak": "sk"}, "cn-hangzhou", func() time.Time { return signedAt })
			if ok, err := a.Verify(r, "bucket", "1234+-/123/1.txt"); !ok || err != nil {
				t.Fatalf("Verify = %v, %v", ok, err)
			}
		})
	}
}

func canonicalLines(t *testing.T, target string, header http.Header) []string {
	t.Helper()
	r := httptest.NewRequest("GET", target, nil)
	for name, values := range header {
		for _, v := range values {
			r.Header.Add(name, v)
		}
	}
	bucket, key := parseAddress(r, "")
	return strings.Split(canonicalRequestV4(r, bucket, key, nil, false), "\n")
}

func TestV4CanonicalQuery(t *testing.T) {
	cases := map[string]string{
		"/b/?bucketInfo":          "bucketInfo",
		"/b/k?objectMeta":         "objectMeta",
		"/b/?delete":              "delete",
		"/b/?list-type=2&prefix=": "list-type=2&prefix",
		"/b/?a-x=1&a=1":           "a=1&a-x=1",
		"/b/?k=a%20b%2Bc":         "k=a%20b%2Bc",
	}
	for target, want := range cases {
		if got := canonicalLines(t, target, nil)[2]; got != want {
			t.Errorf("%s: query = %q, want %q", target, got, want)
		}
	}
}

func TestRepeatedHeadersJoinWithComma(t *testing.T) {
	h := http.Header{}
	h.Add("x-oss-meta-tag", "a")
	h.Add("x-oss-meta-tag", " b ")
	v4 := strings.Join(canonicalLines(t, "/b/k", h), "\n")
	if !strings.Contains(v4, "x-oss-meta-tag:a,b\n") {
		t.Errorf("V4 canonical request lacks the joined header:\n%s", v4)
	}
	r := httptest.NewRequest("GET", "/b/k", nil)
	r.Header = h
	if v1 := stringToSignV1(r, "b", "k", "date"); !strings.Contains(v1, "x-oss-meta-tag:a,b\n") {
		t.Errorf("V1 string to sign lacks the joined header:\n%s", v1)
	}
}

// TestV1MatchesSDKVector replays the SDK's V1 header vector.
func TestV1MatchesSDKVector(t *testing.T) {
	const date = "Wed, 28 Dec 2022 10:27:41 GMT"
	r := httptest.NewRequest("PUT", "/examplebucket/nelson", nil)
	r.Header.Set("Content-MD5", "eB5eJF1ptWaXm4bijSPyxw==")
	r.Header.Set("Content-Type", "text/html")
	r.Header.Set("x-oss-meta-author", "alice")
	r.Header.Set("x-oss-meta-magic", "abracadabra")
	r.Header.Set("x-oss-date", date)
	r.Header.Set("Date", date)
	r.Header.Set("Authorization", "OSS ak:kSHKmLxlyEAKtZPkJhG9bZb5k7M=")

	want := "PUT\neB5eJF1ptWaXm4bijSPyxw==\ntext/html\n" + date + "\nx-oss-date:" + date +
		"\nx-oss-meta-author:alice\nx-oss-meta-magic:abracadabra\n/examplebucket/nelson"
	if got := stringToSignV1(r, "examplebucket", "nelson", date); got != want {
		t.Fatalf("string to sign = %q, want %q", got, want)
	}
	signedAt, _ := http.ParseTime(date)
	a := NewAuthenticator(map[string]string{"ak": "sk"}, "cn-hangzhou", func() time.Time { return signedAt })
	if ok, err := a.Verify(r, "examplebucket", "nelson"); !ok || err != nil {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
}

func TestV1SubResources(t *testing.T) {
	r := httptest.NewRequest("GET", "/b/k?response-content-type=text%2Fplain&acl&prefix=a", nil)
	got := stringToSignV1(r, "b", "k", "date")
	if !strings.HasSuffix(got, "\n/b/k?acl&response-content-type=text/plain") {
		t.Fatalf("resource = %q", got[strings.LastIndex(got, "\n")+1:])
	}
}

func TestURIEncode(t *testing.T) {
	cases := map[string]string{" ": "%20", "+": "%2B", "~": "~", "中": "%E4%B8%AD", "%": "%25", "a/b": "a%2Fb"}
	for in, want := range cases {
		if got := uriEncode(in, true); got != want {
			t.Errorf("uriEncode(%q) = %q, want %q", in, got, want)
		}
		// The SDK encodes query parameters with url.QueryEscape and turns '+' into %20.
		if sdk := strings.ReplaceAll(url.QueryEscape(in), "+", "%20"); sdk != want {
			t.Errorf("SDK encodes %q as %q, want %q", in, sdk, want)
		}
	}
	if got := uriEncode("a/b c", false); got != "a/b%20c" {
		t.Errorf("path encoding = %q", got)
	}
}
