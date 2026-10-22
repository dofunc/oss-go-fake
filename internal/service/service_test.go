package service

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/dofunc/oss-go-fake/internal/storage"
	"github.com/dofunc/oss-go-fake/internal/storage/localfs"
)

func newService(t *testing.T, keys ...string) *Service {
	t.Helper()
	store, err := localfs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(store)
	if err := s.PutBucket(context.Background(), "bucket", storage.ACLPrivate); err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if _, err := s.Put(context.Background(), "bucket", k, strings.NewReader("x"), storage.ObjectMeta{}, true); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestInvalidBucketNames(t *testing.T) {
	s := newService(t)
	for _, name := range []string{"ab", "-abc", "Abc", "abc-", strings.Repeat("a", 64)} {
		if err := s.PutBucket(context.Background(), name, storage.ACLPrivate); KindOf(err) != KindInvalidBucketName {
			t.Errorf("%q: err = %v", name, err)
		}
	}
}

func TestInvalidObjectNames(t *testing.T) {
	s := newService(t)
	for _, key := range []string{"", "/a", `\a`, strings.Repeat("a", 1024), "\xff\xfe"} {
		_, err := s.Put(context.Background(), "bucket", key, strings.NewReader("x"), storage.ObjectMeta{}, true)
		if KindOf(err) != KindInvalidObjectName {
			t.Errorf("%.10q: err = %v", key, err)
		}
	}
}

func keysOf(objects []storage.Object) []string {
	keys := make([]string, len(objects))
	for i, o := range objects {
		keys[i] = o.Key
	}
	return keys
}

func TestListFoldsByDelimiter(t *testing.T) {
	s := newService(t, "a/1", "a/2", "b")
	res, err := s.List(context.Background(), "bucket", ListQuery{Delimiter: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(keysOf(res.Objects), []string{"b"}) || !slices.Equal(res.CommonPrefixes, []string{"a/"}) {
		t.Fatalf("objects = %v, prefixes = %v", keysOf(res.Objects), res.CommonPrefixes)
	}
}

func TestListContinuationToken(t *testing.T) {
	s := newService(t, "k1", "k2", "k3")
	first, err := s.List(context.Background(), "bucket", ListQuery{MaxKeys: "2"})
	if err != nil {
		t.Fatal(err)
	}
	if !first.IsTruncated || !slices.Equal(keysOf(first.Objects), []string{"k1", "k2"}) {
		t.Fatalf("first page = %v, truncated %v", keysOf(first.Objects), first.IsTruncated)
	}
	second, err := s.List(context.Background(), "bucket", ListQuery{MaxKeys: "2", Token: first.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	if second.IsTruncated || !slices.Equal(keysOf(second.Objects), []string{"k3"}) {
		t.Fatalf("second page = %v, truncated %v", keysOf(second.Objects), second.IsTruncated)
	}
}

func TestListFoldedPagesDoNotRepeatPrefixes(t *testing.T) {
	var keys []string
	for i := range 150 {
		keys = append(keys, "a/"+strings.Repeat("x", i+1))
	}
	s := newService(t, append(keys, "b/1", "c")...)
	first, err := s.List(context.Background(), "bucket", ListQuery{Delimiter: "/", MaxKeys: "2"})
	if err != nil {
		t.Fatal(err)
	}
	if !first.IsTruncated || !slices.Equal(first.CommonPrefixes, []string{"a/", "b/"}) || len(first.Objects) != 0 {
		t.Fatalf("first page = %v %v", first.CommonPrefixes, keysOf(first.Objects))
	}
	second, err := s.List(context.Background(), "bucket", ListQuery{Delimiter: "/", MaxKeys: "2", Token: first.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	if second.IsTruncated || len(second.CommonPrefixes) != 0 || !slices.Equal(keysOf(second.Objects), []string{"c"}) {
		t.Fatalf("second page = %v %v", second.CommonPrefixes, keysOf(second.Objects))
	}
}

func TestListRejectsBadArguments(t *testing.T) {
	s := newService(t)
	for _, q := range []ListQuery{{MaxKeys: "0"}, {MaxKeys: "1001"}, {MaxKeys: "ten"}, {Token: "!!not-base64"}} {
		if _, err := s.List(context.Background(), "bucket", q); KindOf(err) != KindInvalidArgument {
			t.Errorf("%+v: err = %v", q, err)
		}
	}
}

func TestAllowed(t *testing.T) {
	public := storage.Bucket{Name: "pub", ACL: storage.ACLPublicRead}
	private := storage.Bucket{Name: "pri", ACL: storage.ACLPrivate}
	cases := []struct {
		bucket storage.Bucket
		op     Operation
		want   bool
	}{
		{public, OpGetObject, true},
		{public, OpHeadObject, true},
		{public, OpGetObjectMeta, true},
		{public, OpListObjects, false},
		{public, OpGetBucketInfo, false},
		{public, OpWrite, false},
		{private, OpGetObject, false},
		{private, OpHeadObject, false},
	}
	for _, c := range cases {
		if got := Allowed(c.bucket, c.op, false); got != c.want {
			t.Errorf("anonymous %s op %d = %v, want %v", c.bucket.ACL, c.op, got, c.want)
		}
		if !Allowed(c.bucket, c.op, true) {
			t.Errorf("authenticated %s op %d denied", c.bucket.ACL, c.op)
		}
	}
}

func TestDeleteMissingObjectSucceeds(t *testing.T) {
	s := newService(t)
	if err := s.Delete(context.Background(), "bucket", "nope"); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestMissingBucketAndKey(t *testing.T) {
	s := newService(t)
	if _, err := s.Head(context.Background(), "bucket", "nope"); KindOf(err) != KindNoSuchKey {
		t.Errorf("missing key: %v", err)
	}
	if _, err := s.GetBucket(context.Background(), "nobucket"); KindOf(err) != KindNoSuchBucket {
		t.Errorf("missing bucket: %v", err)
	}
}
