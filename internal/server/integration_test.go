package server_test

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/signer"

	"github.com/dofunc/oss-go-fake/internal/config"
	"github.com/dofunc/oss-go-fake/internal/protocol"
	fakeoss "github.com/dofunc/oss-go-fake/internal/protocol/oss"
	"github.com/dofunc/oss-go-fake/internal/protocol/s3"
	"github.com/dofunc/oss-go-fake/internal/server"
	"github.com/dofunc/oss-go-fake/internal/service"
	"github.com/dofunc/oss-go-fake/internal/storage"
	"github.com/dofunc/oss-go-fake/internal/storage/localfs"
)

const (
	testAK      = "fake-ak"
	testSK      = "fake-sk"
	testRegion  = "cn-hangzhou"
	allowedSite = "http://allowed.example"
)

var defaultBuckets = map[string]storage.ACL{
	"bucket": storage.ACLPrivate,
	"other":  storage.ACLPrivate,
	"pub":    storage.ACLPublicRead,
	"cors":   storage.ACLPrivate,
}

var corsRules = map[string][]config.CORSRule{
	"cors": {{
		AllowedOrigins: []string{allowedSite},
		AllowedMethods: []string{"GET", "PUT"},
		AllowedHeaders: []string{"content-type", "x-oss-*"},
		ExposeHeaders:  []string{"ETag"},
		MaxAgeSeconds:  600,
	}},
}

type env struct {
	url     string
	host    string
	dataDir string
	svc     *service.Service
}

func startEnv(t *testing.T, dataDir string, buckets map[string]storage.ACL) *env {
	t.Helper()
	store, err := localfs.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(store)
	for name, acl := range buckets {
		if err := svc.EnsureBucket(context.Background(), name, acl); err != nil {
			t.Fatal(err)
		}
	}
	h := fakeoss.New(svc, fakeoss.Options{Region: testRegion, AccessKeys: map[string]string{testAK: testSK}, CORS: corsRules})
	srv := httptest.NewServer(server.Handler([]protocol.Protocol{h}, []protocol.Protocol{s3.Reserved{}}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return &env{url: srv.URL, host: u.Host, dataDir: dataDir, svc: svc}
}

func (e *env) client(v sdk.SignatureVersionType, ak, sk, region string) *sdk.Client {
	cfg := sdk.LoadDefaultConfig().
		WithCredentialsProvider(credentials.NewStaticCredentialsProvider(ak, sk)).
		WithRegion(region).
		WithEndpoint(e.host).
		WithUsePathStyle(true).
		WithDisableSSL(true).
		WithSignatureVersion(v).
		WithRetryMaxAttempts(1)
	return sdk.NewClient(cfg)
}

func (e *env) seed(t *testing.T, bucket string, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, err := e.svc.Put(context.Background(), bucket, k, strings.NewReader("x"), storage.ObjectMeta{ContentType: "text/plain"}, true); err != nil {
			t.Fatal(err)
		}
	}
}

// signed builds a request signed by the SDK's own signer, for cases the SDK client refuses to
// send or that need a tampered request. signedAt zero means now.
func (e *env) signed(t *testing.T, v sdk.SignatureVersionType, method, bucket, key string, header http.Header, body []byte, signedAt time.Time) *http.Request {
	t.Helper()
	u := &url.URL{Scheme: "http", Host: e.host, Path: "/" + bucket + "/" + key}
	r, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		for _, value := range values {
			r.Header.Add(name, value)
		}
	}
	cred, _ := credentials.NewStaticCredentialsProvider(testAK, testSK).GetCredentials(context.Background())
	ctx := &signer.SigningContext{
		Bucket: sdk.Ptr(bucket), Request: r, Credentials: &cred,
		Product: sdk.Ptr("oss"), Region: sdk.Ptr(testRegion), Time: signedAt,
	}
	if key != "" {
		ctx.Key = sdk.Ptr(key)
	}
	var s signer.Signer = &signer.SignerV4{}
	if v == sdk.SignatureVersionV1 {
		s = &signer.SignerV1{}
	}
	if err := s.Sign(context.Background(), ctx); err != nil {
		t.Fatal(err)
	}
	return r
}

type errorBody struct {
	Code string `xml:"Code"`
}

// do sends r and returns the status with the OSS error code, read from x-oss-err.
func do(t *testing.T, r *http.Request) (int, string, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer closeOrFail(t, resp.Body)
	body, _ := io.ReadAll(resp.Body)
	var e errorBody
	if raw, err := base64.StdEncoding.DecodeString(resp.Header.Get("x-oss-err")); err == nil && len(raw) > 0 {
		if err := xml.Unmarshal(raw, &e); err != nil {
			t.Fatalf("x-oss-err is not XML: %v", err)
		}
	}
	return resp.StatusCode, e.Code, body
}

func closeOrFail(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func codeOf(err error) string {
	var se *sdk.ServiceError
	if errors.As(err, &se) {
		return se.Code
	}
	return ""
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if got := codeOf(err); got != code {
		t.Fatalf("error code = %q (%v), want %s", got, err, code)
	}
}

var versions = []struct {
	name string
	v    sdk.SignatureVersionType
}{{"V1", sdk.SignatureVersionV1}, {"V4", sdk.SignatureVersionV4}}

// eachVersion runs fn against a fresh server once per signature version.
func eachVersion(t *testing.T, fn func(t *testing.T, e *env, c *sdk.Client, v sdk.SignatureVersionType)) {
	for _, ver := range versions {
		t.Run(ver.name, func(t *testing.T) {
			e := startEnv(t, filepath.Join(t.TempDir(), "data"), defaultBuckets)
			fn(t, e, e.client(ver.v, testAK, testSK, testRegion), ver.v)
		})
	}
}

var ctx = context.Background()

func putString(t *testing.T, c *sdk.Client, bucket, key, content string) *sdk.PutObjectResult {
	t.Helper()
	res, err := c.PutObject(ctx, &sdk.PutObjectRequest{Bucket: sdk.Ptr(bucket), Key: sdk.Ptr(key), Body: strings.NewReader(content)})
	if err != nil {
		t.Fatalf("PutObject %s: %v", key, err)
	}
	return res
}

func getString(t *testing.T, c *sdk.Client, bucket, key string) string {
	t.Helper()
	res, err := c.GetObject(ctx, &sdk.GetObjectRequest{Bucket: sdk.Ptr(bucket), Key: sdk.Ptr(key)})
	if err != nil {
		t.Fatalf("GetObject %s: %v", key, err)
	}
	defer closeOrFail(t, res.Body)
	data, _ := io.ReadAll(res.Body)
	return string(data)
}

func TestListBuckets(t *testing.T) {
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		res, err := c.ListBuckets(ctx, &sdk.ListBucketsRequest{})
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, b := range res.Buckets {
			names = append(names, *b.Name)
		}
		slices.Sort(names)
		if !slices.Equal(names, []string{"bucket", "cors", "other", "pub"}) {
			t.Fatalf("buckets = %v", names)
		}
	})
}

func TestPutBucket(t *testing.T) {
	eachVersion(t, func(t *testing.T, e *env, c *sdk.Client, v sdk.SignatureVersionType) {
		if _, err := c.PutBucket(ctx, &sdk.PutBucketRequest{Bucket: sdk.Ptr("fresh")}); err != nil {
			t.Fatal(err)
		}
		_, err := c.PutBucket(ctx, &sdk.PutBucketRequest{Bucket: sdk.Ptr("fresh")})
		wantCode(t, err, "BucketAlreadyExists")
		status, code, _ := do(t, e.signed(t, v, "PUT", "Invalid_Name", "", nil, nil, time.Time{}))
		if status != http.StatusBadRequest || code != "InvalidBucketName" {
			t.Fatalf("invalid name: %d %s", status, code)
		}
	})
}

func TestDeleteBucket(t *testing.T) {
	eachVersion(t, func(t *testing.T, e *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		if _, err := c.PutBucket(ctx, &sdk.PutBucketRequest{Bucket: sdk.Ptr("empty")}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.DeleteBucket(ctx, &sdk.DeleteBucketRequest{Bucket: sdk.Ptr("empty")}); err != nil {
			t.Fatal(err)
		}
		e.seed(t, "bucket", "k")
		_, err := c.DeleteBucket(ctx, &sdk.DeleteBucketRequest{Bucket: sdk.Ptr("bucket")})
		wantCode(t, err, "BucketNotEmpty")
		_, err = c.DeleteBucket(ctx, &sdk.DeleteBucketRequest{Bucket: sdk.Ptr("missing")})
		wantCode(t, err, "NoSuchBucket")
	})
}

func TestGetBucketInfo(t *testing.T) {
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		res, err := c.GetBucketInfo(ctx, &sdk.GetBucketInfoRequest{Bucket: sdk.Ptr("pub")})
		if err != nil {
			t.Fatal(err)
		}
		info := res.BucketInfo
		if *info.Name != "pub" || *info.ACL != "public-read" || *info.Location != "oss-"+testRegion {
			t.Fatalf("info = %s %s %s", *info.Name, *info.ACL, *info.Location)
		}
	})
}

func TestListObjectsMarker(t *testing.T) {
	eachVersion(t, func(t *testing.T, e *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		var keys []string
		for i := range 250 {
			keys = append(keys, fmt.Sprintf("k%03d", i))
		}
		e.seed(t, "bucket", keys...)
		var got []string
		marker, pages := "", 0
		for {
			res, err := c.ListObjects(ctx, &sdk.ListObjectsRequest{Bucket: sdk.Ptr("bucket"), MaxKeys: 100, Marker: sdk.Ptr(marker)})
			if err != nil {
				t.Fatal(err)
			}
			pages++
			for _, o := range res.Contents {
				got = append(got, *o.Key)
			}
			if !res.IsTruncated {
				break
			}
			if *res.NextMarker != got[len(got)-1] {
				t.Fatalf("NextMarker = %s, last key %s", *res.NextMarker, got[len(got)-1])
			}
			marker = *res.NextMarker
		}
		if pages != 3 || !slices.Equal(got, keys) {
			t.Fatalf("pages = %d, %d keys", pages, len(got))
		}
	})
}

func prefixes(res *sdk.ListObjectsV2Result) []string {
	var out []string
	for _, p := range res.CommonPrefixes {
		out = append(out, *p.Prefix)
	}
	return out
}

func contents(res *sdk.ListObjectsV2Result) []string {
	var out []string
	for _, o := range res.Contents {
		out = append(out, *o.Key)
	}
	return out
}

func TestListObjectsV2Delimiter(t *testing.T) {
	eachVersion(t, func(t *testing.T, e *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		var keys []string
		for i := 1; i <= 150; i++ {
			keys = append(keys, fmt.Sprintf("a/%d", i))
		}
		e.seed(t, "bucket", append(keys, "b/1", "c")...)

		whole, err := c.ListObjectsV2(ctx, &sdk.ListObjectsV2Request{Bucket: sdk.Ptr("bucket"), Delimiter: sdk.Ptr("/"), MaxKeys: 100})
		if err != nil {
			t.Fatal(err)
		}
		if whole.IsTruncated || !slices.Equal(prefixes(whole), []string{"a/", "b/"}) || !slices.Equal(contents(whole), []string{"c"}) {
			t.Fatalf("one page: truncated %v, prefixes %v, contents %v", whole.IsTruncated, prefixes(whole), contents(whole))
		}

		first, err := c.ListObjectsV2(ctx, &sdk.ListObjectsV2Request{Bucket: sdk.Ptr("bucket"), Delimiter: sdk.Ptr("/"), MaxKeys: 2})
		if err != nil {
			t.Fatal(err)
		}
		if !first.IsTruncated || first.NextContinuationToken == nil || !slices.Equal(prefixes(first), []string{"a/", "b/"}) || len(first.Contents) != 0 {
			t.Fatalf("first page: truncated %v, prefixes %v, contents %v", first.IsTruncated, prefixes(first), contents(first))
		}
		second, err := c.ListObjectsV2(ctx, &sdk.ListObjectsV2Request{Bucket: sdk.Ptr("bucket"), Delimiter: sdk.Ptr("/"), MaxKeys: 2, ContinuationToken: first.NextContinuationToken})
		if err != nil {
			t.Fatal(err)
		}
		if second.IsTruncated || len(second.CommonPrefixes) != 0 || !slices.Equal(contents(second), []string{"c"}) {
			t.Fatalf("second page: truncated %v, prefixes %v, contents %v", second.IsTruncated, prefixes(second), contents(second))
		}
	})
}

func TestGetObjectMeta(t *testing.T) {
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		put := putString(t, c, "bucket", "k", "hello")
		res, err := c.GetObjectMeta(ctx, &sdk.GetObjectMetaRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k")})
		if err != nil {
			t.Fatal(err)
		}
		sum := md5.Sum([]byte("hello"))
		wantETag := fmt.Sprintf(`"%X"`, sum)
		if res.ContentLength != 5 || *res.ETag != wantETag || *put.ETag != wantETag || res.LastModified == nil {
			t.Fatalf("meta = %d %s, put ETag %s", res.ContentLength, *res.ETag, *put.ETag)
		}
	})
}

func TestGetObjectResponseOverrides(t *testing.T) {
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		putString(t, c, "bucket", "k", "hello")
		res, err := c.GetObject(ctx, &sdk.GetObjectRequest{
			Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k"),
			ResponseContentType: sdk.Ptr("image/png"), ResponseContentDisposition: sdk.Ptr(`attachment; filename="a b.png"`),
		})
		if err != nil {
			t.Fatal(err)
		}
		closeOrFail(t, res.Body)
		if res.Headers.Get("Content-Type") != "image/png" || res.Headers.Get("Content-Disposition") != `attachment; filename="a b.png"` {
			t.Fatalf("headers = %v", res.Headers)
		}
	})
}

func TestForbidOverwrite(t *testing.T) {
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		putString(t, c, "bucket", "k", "original")
		_, err := c.PutObject(ctx, &sdk.PutObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k"), ForbidOverwrite: sdk.Ptr("true"), Body: strings.NewReader("new")})
		wantCode(t, err, "FileAlreadyExists")
		if got := getString(t, c, "bucket", "k"); got != "original" {
			t.Fatalf("content = %q", got)
		}
		putString(t, c, "bucket", "src", "source")
		_, err = c.CopyObject(ctx, &sdk.CopyObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k"), SourceKey: sdk.Ptr("src"), ForbidOverwrite: sdk.Ptr("true")})
		wantCode(t, err, "FileAlreadyExists")
	})
}

func TestRestartAppliesBucketACL(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	first := startEnv(t, dataDir, map[string]storage.ACL{"flip": storage.ACLPrivate})
	putString(t, first.client(sdk.SignatureVersionV4, testAK, testSK, testRegion), "flip", "k", "kept")
	if status, _, _ := do(t, mustRequest(t, "GET", first.url+"/flip/k")); status != http.StatusForbidden {
		t.Fatalf("anonymous read of a private bucket: %d", status)
	}
	second := startEnv(t, dataDir, map[string]storage.ACL{"flip": storage.ACLPublicRead})
	status, _, body := do(t, mustRequest(t, "GET", second.url+"/flip/k"))
	if status != http.StatusOK || string(body) != "kept" {
		t.Fatalf("anonymous read after restart: %d %q", status, body)
	}
}

func mustRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestObjectRoundTrip(t *testing.T) {
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		_, err := c.PutObject(ctx, &sdk.PutObjectRequest{
			Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("dir/file.txt"), ContentType: sdk.Ptr("text/plain"),
			Metadata: map[string]string{"owner": "alice"}, Body: strings.NewReader("hello world"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := getString(t, c, "bucket", "dir/file.txt"); got != "hello world" {
			t.Fatalf("content = %q", got)
		}
		head, err := c.HeadObject(ctx, &sdk.HeadObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("dir/file.txt")})
		if err != nil {
			t.Fatal(err)
		}
		if head.ContentLength != 11 || *head.ContentType != "text/plain" || head.Metadata["owner"] != "alice" {
			t.Fatalf("head = %d %s %v", head.ContentLength, *head.ContentType, head.Metadata)
		}
		if _, err := c.DeleteObject(ctx, &sdk.DeleteObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("dir/file.txt")}); err != nil {
			t.Fatal(err)
		}
		_, err = c.HeadObject(ctx, &sdk.HeadObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("dir/file.txt")})
		wantCode(t, err, "NoSuchKey")
	})
}

func TestRepeatedHeaders(t *testing.T) {
	eachVersion(t, func(t *testing.T, e *env, _ *sdk.Client, v sdk.SignatureVersionType) {
		header := http.Header{}
		header.Add("x-oss-meta-tag", "a")
		header.Add("x-oss-meta-tag", "b")
		if status, code, _ := do(t, e.signed(t, v, "PUT", "bucket", "k", header, []byte("x"), time.Time{})); status != http.StatusOK {
			t.Fatalf("signed repeated header: %d %s", status, code)
		}
		r := e.signed(t, v, "PUT", "bucket", "k", header, []byte("x"), time.Time{})
		r.Header["X-Oss-Meta-Tag"][1] = "tampered"
		if status, code, _ := do(t, r); status != http.StatusForbidden || code != "SignatureDoesNotMatch" {
			t.Fatalf("tampered repeated header: %d %s", status, code)
		}
	})
}

func TestHeadObjectErrors(t *testing.T) {
	eachVersion(t, func(t *testing.T, e *env, c *sdk.Client, v sdk.SignatureVersionType) {
		putString(t, c, "bucket", "k", "x")
		_, err := c.HeadObject(ctx, &sdk.HeadObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("missing")})
		wantCode(t, err, "NoSuchKey")
		_, err = c.HeadObject(ctx, &sdk.HeadObjectRequest{Bucket: sdk.Ptr("nobucket"), Key: sdk.Ptr("k")})
		wantCode(t, err, "NoSuchBucket")
		_, err = e.client(v, testAK, "wrong", testRegion).HeadObject(ctx, &sdk.HeadObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k")})
		wantCode(t, err, "SignatureDoesNotMatch")
	})
}

func TestAnonymousCannotListPublicBucket(t *testing.T) {
	e := startEnv(t, filepath.Join(t.TempDir(), "data"), defaultBuckets)
	status, code, _ := do(t, mustRequest(t, "GET", e.url+"/pub/?list-type=2"))
	if status != http.StatusForbidden || code != "AccessDenied" {
		t.Fatalf("anonymous list: %d %s", status, code)
	}
}

func TestCopyObject(t *testing.T) {
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		src, err := c.PutObject(ctx, &sdk.PutObjectRequest{
			Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("src"), ContentType: sdk.Ptr("text/plain"),
			Metadata: map[string]string{"a": "1"}, Body: strings.NewReader("payload"),
		})
		if err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			name, bucket, directive string
			meta                    map[string]string
			wantType                string
			wantMeta                map[string]string
		}{
			{"same bucket COPY", "bucket", "COPY", nil, "text/plain", map[string]string{"a": "1"}},
			{"cross bucket REPLACE", "other", "REPLACE", map[string]string{"b": "2"}, "text/html", map[string]string{"b": "2"}},
		}
		for _, cs := range cases {
			req := &sdk.CopyObjectRequest{
				Bucket: sdk.Ptr(cs.bucket), Key: sdk.Ptr("dst"), SourceBucket: sdk.Ptr("bucket"), SourceKey: sdk.Ptr("src"),
				MetadataDirective: sdk.Ptr(cs.directive), Metadata: cs.meta,
			}
			if cs.directive == "REPLACE" {
				req.ContentType = sdk.Ptr(cs.wantType)
			}
			res, err := c.CopyObject(ctx, req)
			if err != nil {
				t.Fatalf("%s: %v", cs.name, err)
			}
			head, err := c.HeadObject(ctx, &sdk.HeadObjectRequest{Bucket: sdk.Ptr(cs.bucket), Key: sdk.Ptr("dst")})
			if err != nil {
				t.Fatal(err)
			}
			if *res.ETag != *src.ETag || *head.ETag != *src.ETag || *head.ContentType != cs.wantType || len(head.Metadata) != len(cs.wantMeta) {
				t.Fatalf("%s: etag %s/%s, type %s, meta %v", cs.name, *res.ETag, *src.ETag, *head.ContentType, head.Metadata)
			}
			for k, v := range cs.wantMeta {
				if head.Metadata[k] != v {
					t.Fatalf("%s: meta %v", cs.name, head.Metadata)
				}
			}
		}
	})
}

func TestDeleteMultipleObjects(t *testing.T) {
	eachVersion(t, func(t *testing.T, e *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		for _, quiet := range []bool{false, true} {
			e.seed(t, "bucket", "k1", "k2")
			res, err := c.DeleteMultipleObjects(ctx, &sdk.DeleteMultipleObjectsRequest{
				Bucket: sdk.Ptr("bucket"), Quiet: quiet,
				Objects: []sdk.DeleteObject{{Key: sdk.Ptr("k1")}, {Key: sdk.Ptr("k2")}, {Key: sdk.Ptr("missing")}},
			})
			if err != nil {
				t.Fatal(err)
			}
			want := 3
			if quiet {
				want = 0
			}
			if len(res.DeletedObjects) != want {
				t.Fatalf("quiet=%v: %d deleted entries, want %d", quiet, len(res.DeletedObjects), want)
			}
			list, err := c.ListObjectsV2(ctx, &sdk.ListObjectsV2Request{Bucket: sdk.Ptr("bucket")})
			if err != nil {
				t.Fatal(err)
			}
			if len(list.Contents) != 0 {
				t.Fatalf("quiet=%v: objects left %v", quiet, contents(list))
			}
		}
	})
}

func TestRange(t *testing.T) {
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		putString(t, c, "bucket", "k", "0123456789")
		res, err := c.GetObject(ctx, &sdk.GetObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k"), Range: sdk.Ptr("bytes=2-4")})
		if err != nil {
			t.Fatal(err)
		}
		defer closeOrFail(t, res.Body)
		data, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusPartialContent || *res.ContentRange != "bytes 2-4/10" || string(data) != "234" {
			t.Fatalf("range: %d %s %q", res.StatusCode, *res.ContentRange, data)
		}
	})
}

func TestPresignedURLs(t *testing.T) {
	eachVersion(t, func(t *testing.T, e *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		putString(t, c, "bucket", "k", "presigned")
		get, err := c.Presign(ctx, &sdk.GetObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k")})
		if err != nil {
			t.Fatal(err)
		}
		if status, code, body := do(t, mustRequest(t, "GET", get.URL)); status != http.StatusOK || string(body) != "presigned" {
			t.Fatalf("presigned GET: %d %s %q", status, code, body)
		}

		tampered := strings.Replace(get.URL, "/bucket/k?", "/bucket/other?", 1)
		if status, code, _ := do(t, mustRequest(t, "GET", tampered)); status != http.StatusForbidden || code != "SignatureDoesNotMatch" {
			t.Fatalf("tampered key: %d %s", status, code)
		}

		put, err := c.Presign(ctx, &sdk.PutObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("uploaded")})
		if err != nil {
			t.Fatal(err)
		}
		r, _ := http.NewRequest("PUT", put.URL, strings.NewReader("via url"))
		for name, value := range put.SignedHeaders {
			r.Header.Set(name, value)
		}
		if status, code, _ := do(t, r); status != http.StatusOK {
			t.Fatalf("presigned PUT: %d %s", status, code)
		}
		if got := getString(t, c, "bucket", "uploaded"); got != "via url" {
			t.Fatalf("uploaded = %q", got)
		}
	})
}

func TestPresignedURLExpires(t *testing.T) {
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		putString(t, c, "bucket", "k", "x")
		res, err := c.Presign(ctx, &sdk.GetObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k")}, sdk.PresignExpires(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		if status, code, _ := do(t, mustRequest(t, "GET", res.URL)); status != http.StatusForbidden || code != "AccessDenied" {
			t.Fatalf("expired URL: %d %s", status, code)
		}
	})
}

func TestCredentialErrors(t *testing.T) {
	eachVersion(t, func(t *testing.T, e *env, _ *sdk.Client, v sdk.SignatureVersionType) {
		_, err := e.client(v, "nobody", testSK, testRegion).GetObject(ctx, &sdk.GetObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k")})
		wantCode(t, err, "InvalidAccessKeyId")
		_, err = e.client(v, testAK, "wrong", testRegion).GetObject(ctx, &sdk.GetObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k")})
		wantCode(t, err, "SignatureDoesNotMatch")
		status, code, _ := do(t, e.signed(t, v, "GET", "bucket", "k", nil, nil, time.Now().Add(-16*time.Minute)))
		if status != http.StatusForbidden || code != "RequestTimeTooSkewed" {
			t.Fatalf("skewed: %d %s", status, code)
		}
	})
}

func TestV4RegionMismatch(t *testing.T) {
	e := startEnv(t, filepath.Join(t.TempDir(), "data"), defaultBuckets)
	_, err := e.client(sdk.SignatureVersionV4, testAK, testSK, "cn-beijing").GetObject(ctx, &sdk.GetObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k")})
	wantCode(t, err, "SignatureDoesNotMatch")
}

func TestMissingBucketAndObject(t *testing.T) {
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		_, err := c.GetObject(ctx, &sdk.GetObjectRequest{Bucket: sdk.Ptr("undeclared"), Key: sdk.Ptr("k")})
		wantCode(t, err, "NoSuchBucket")
		_, err = c.GetObject(ctx, &sdk.GetObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("missing")})
		wantCode(t, err, "NoSuchKey")
	})
}

func TestBadContentMD5(t *testing.T) {
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		empty := md5.Sum(nil)
		_, err := c.PutObject(ctx, &sdk.PutObjectRequest{
			Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k"), ContentMD5: sdk.Ptr(base64.StdEncoding.EncodeToString(empty[:])),
			Body: strings.NewReader("not empty"),
		})
		wantCode(t, err, "InvalidDigest")
		_, err = c.HeadObject(ctx, &sdk.HeadObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("k")})
		wantCode(t, err, "NoSuchKey")
	})
}

func TestPathLikeKeysStayInside(t *testing.T) {
	eachVersion(t, func(t *testing.T, e *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		keys := []string{"../escape", "%2e%2e/x", "a//b", "../../../../etc/x"}
		for _, k := range keys {
			putString(t, c, "bucket", k, "content of "+k)
		}
		for _, k := range keys {
			if got := getString(t, c, "bucket", k); got != "content of "+k {
				t.Fatalf("%s = %q", k, got)
			}
		}
		parent, err := os.ReadDir(filepath.Dir(e.dataDir))
		if err != nil {
			t.Fatal(err)
		}
		if len(parent) != 1 || parent[0].Name() != "data" {
			t.Fatalf("files appeared next to the data dir: %v", parent)
		}
	})
}

// pattern yields a deterministic, incompressible-enough byte stream without holding it in memory.
type pattern struct{ n int }

func (p *pattern) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte((p.n*7 + p.n/251) % 256)
		p.n++
	}
	return len(b), nil
}

func TestLargeObjectStreams(t *testing.T) {
	const size = 50 << 20
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		runtime.GC()
		var peak uint64
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			var m runtime.MemStats
			for {
				select {
				case <-stop:
					return
				case <-time.After(20 * time.Millisecond):
					runtime.ReadMemStats(&m)
					peak = max(peak, m.HeapInuse)
				}
			}
		})

		up := md5.New()
		_, err := c.PutObject(ctx, &sdk.PutObjectRequest{
			Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("big"), ContentLength: sdk.Ptr(int64(size)),
			Body: io.TeeReader(io.LimitReader(&pattern{}, size), up),
		})
		if err != nil {
			t.Fatal(err)
		}
		res, err := c.GetObject(ctx, &sdk.GetObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr("big")})
		if err != nil {
			t.Fatal(err)
		}
		down := md5.New()
		n, err := io.Copy(down, res.Body)
		closeOrFail(t, res.Body)
		close(stop)
		wg.Wait()
		if err != nil || n != size || !bytes.Equal(up.Sum(nil), down.Sum(nil)) {
			t.Fatalf("downloaded %d bytes, err %v, digests equal %v", n, err, bytes.Equal(up.Sum(nil), down.Sum(nil)))
		}
		if peak > size/2 {
			t.Fatalf("heap in use peaked at %d MB for a %d MB object", peak>>20, size>>20)
		}
	})
}

func TestConcurrentClients(t *testing.T) {
	eachVersion(t, func(t *testing.T, _ *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		var wg sync.WaitGroup
		for i := range 20 {
			wg.Go(func() {
				key := fmt.Sprintf("client-%d", i)
				content := strings.Repeat(key, 100)
				if _, err := c.PutObject(ctx, &sdk.PutObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr(key), Body: strings.NewReader(content)}); err != nil {
					t.Error(err)
					return
				}
				res, err := c.GetObject(ctx, &sdk.GetObjectRequest{Bucket: sdk.Ptr("bucket"), Key: sdk.Ptr(key)})
				if err != nil {
					t.Error(err)
					return
				}
				data, _ := io.ReadAll(res.Body)
				closeOrFail(t, res.Body)
				if string(data) != content {
					t.Errorf("%s: content mismatch", key)
				}
			})
		}
		wg.Wait()
	})
}

func preflight(t *testing.T, e *env, bucket, origin, method, headers string) *http.Response {
	t.Helper()
	r := mustRequest(t, "OPTIONS", e.url+"/"+bucket+"/k")
	r.Header.Set("Origin", origin)
	r.Header.Set("Access-Control-Request-Method", method)
	if headers != "" {
		r.Header.Set("Access-Control-Request-Headers", headers)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	closeOrFail(t, resp.Body)
	return resp
}

func TestCORS(t *testing.T) {
	eachVersion(t, func(t *testing.T, e *env, c *sdk.Client, _ sdk.SignatureVersionType) {
		ok := preflight(t, e, "cors", allowedSite, "GET", "")
		if ok.StatusCode != http.StatusOK || ok.Header.Get("Access-Control-Allow-Origin") != allowedSite || ok.Header.Get("Access-Control-Max-Age") != "600" {
			t.Fatalf("allowed origin: %d %v", ok.StatusCode, ok.Header)
		}
		if denied := preflight(t, e, "cors", "http://evil.example", "GET", ""); denied.StatusCode != http.StatusForbidden {
			t.Fatalf("foreign origin: %d", denied.StatusCode)
		}
		put := preflight(t, e, "cors", allowedSite, "PUT", "content-type")
		if put.StatusCode != http.StatusOK || put.Header.Get("Access-Control-Allow-Headers") != "content-type" {
			t.Fatalf("private bucket PUT preflight: %d %v", put.StatusCode, put.Header)
		}

		url, err := c.Presign(ctx, &sdk.PutObjectRequest{Bucket: sdk.Ptr("cors"), Key: sdk.Ptr("k")})
		if err != nil {
			t.Fatal(err)
		}
		r, _ := http.NewRequest("PUT", url.URL, strings.NewReader("from browser"))
		r.Header.Set("Origin", allowedSite)
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		closeOrFail(t, resp.Body)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Access-Control-Allow-Origin") != allowedSite {
			t.Fatalf("PUT after preflight: %d %v", resp.StatusCode, resp.Header)
		}

		if denied := preflight(t, e, "cors", allowedSite, "PUT", "x-forbidden"); denied.StatusCode != http.StatusForbidden {
			t.Fatalf("header outside allowed-headers: %d", denied.StatusCode)
		}
	})
}
