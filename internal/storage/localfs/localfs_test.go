package localfs

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dofunc/oss-go-fake/internal/storage"
)

func openStore(t *testing.T, buckets ...string) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	s, err := Open(root)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, b := range buckets {
		if err := s.CreateBucket(context.Background(), storage.Bucket{Name: b, ACL: storage.ACLPrivate, CreatedAt: time.Now()}); err != nil {
			t.Fatalf("CreateBucket %s: %v", b, err)
		}
	}
	return s, root
}

func put(t *testing.T, s *Store, bucket, key, content string) storage.Object {
	t.Helper()
	obj, err := s.PutObject(context.Background(), bucket, key, strings.NewReader(content), storage.ObjectMeta{ContentType: "text/plain"}, true)
	if err != nil {
		t.Fatalf("PutObject %s: %v", key, err)
	}
	return obj
}

func read(t *testing.T, s *Store, bucket, key string, rng *storage.ByteRange) string {
	t.Helper()
	rc, _, err := s.OpenObject(context.Background(), bucket, key, rng)
	if err != nil {
		t.Fatalf("OpenObject %s: %v", key, err)
	}
	defer closeOrFail(t, rc)
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	return string(data)
}

func closeOrFail(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// dataFiles lists every object data file of a bucket.
func dataFiles(t *testing.T, root, bucket string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(filepath.Join(root, bucket, objectsDir), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !strings.HasSuffix(path, metaSuffix) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return files
}

func tmpEntries(t *testing.T, root string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, tmpDir))
	if err != nil {
		t.Fatalf("read tmp: %v", err)
	}
	return entries
}

func TestPutThenRead(t *testing.T) {
	s, _ := openStore(t, "b1")
	put(t, s, "b1", "a/b.txt", "hello")
	obj, err := s.StatObject(context.Background(), "b1", "a/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != 5 || obj.MD5 != md5.Sum([]byte("hello")) || obj.ContentType != "text/plain" {
		t.Fatalf("stat = %+v", obj)
	}
	if got := read(t, s, "b1", "a/b.txt", nil); got != "hello" {
		t.Fatalf("read = %q", got)
	}
}

func TestKeysThatCollideAsPaths(t *testing.T) {
	s, _ := openStore(t, "b1")
	long := strings.Repeat("x", 1023)
	cases := map[string]string{"a": "file", "a/b": "nested", "A": "upper", long: "long"}
	for key, content := range cases {
		put(t, s, "b1", key, content)
	}
	for key, content := range cases {
		if got := read(t, s, "b1", key, nil); got != content {
			t.Errorf("%.10q = %q, want %q", key, got, content)
		}
	}
}

func TestOverwriteRemovesOldData(t *testing.T) {
	s, root := openStore(t, "b1")
	put(t, s, "b1", "k", "first")
	put(t, s, "b1", "k", "second")
	if got := read(t, s, "b1", "k", nil); got != "second" {
		t.Fatalf("read = %q", got)
	}
	if files := dataFiles(t, root, "b1"); len(files) != 1 {
		t.Fatalf("data files = %v, want exactly one", files)
	}
}

func TestForbidOverwrite(t *testing.T) {
	s, _ := openStore(t, "b1")
	put(t, s, "b1", "k", "first")
	_, err := s.PutObject(context.Background(), "b1", "k", strings.NewReader("second"), storage.ObjectMeta{}, false)
	if !errors.Is(err, storage.ErrObjectExists) {
		t.Fatalf("err = %v, want ErrObjectExists", err)
	}
	if got := read(t, s, "b1", "k", nil); got != "first" {
		t.Fatalf("read = %q", got)
	}
}

type failingReader struct{ served bool }

func (f *failingReader) Read(p []byte) (int, error) {
	if !f.served {
		f.served = true
		return copy(p, "partial"), nil
	}
	return 0, errors.New("connection reset")
}

func TestInterruptedWriteLeavesNothing(t *testing.T) {
	s, root := openStore(t, "b1")
	_, err := s.PutObject(context.Background(), "b1", "k", &failingReader{}, storage.ObjectMeta{}, true)
	if err == nil {
		t.Fatal("PutObject succeeded on a failing body")
	}
	if _, err := s.StatObject(context.Background(), "b1", "k"); !errors.Is(err, storage.ErrObjectNotFound) {
		t.Fatalf("stat err = %v, want ErrObjectNotFound", err)
	}
	if entries := tmpEntries(t, root); len(entries) != 0 {
		t.Fatalf(".tmp holds %d entries", len(entries))
	}
	if files := dataFiles(t, root, "b1"); len(files) != 0 {
		t.Fatalf("data files = %v", files)
	}
}

func TestConcurrentWritesToOneKey(t *testing.T) {
	s, root := openStore(t, "b1")
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			if _, err := s.PutObject(context.Background(), "b1", "k", strings.NewReader(fmt.Sprintf("content-%02d", i)), storage.ObjectMeta{}, true); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	obj, err := s.StatObject(context.Background(), "b1", "k")
	if err != nil {
		t.Fatal(err)
	}
	got := read(t, s, "b1", "k", nil)
	if !strings.HasPrefix(got, "content-") || obj.MD5 != md5.Sum([]byte(got)) {
		t.Fatalf("content %q does not match its metadata", got)
	}
	if files := dataFiles(t, root, "b1"); len(files) != 1 {
		t.Fatalf("data files = %d, want 1", len(files))
	}
}

func TestReadsDuringOverwrites(t *testing.T) {
	s, _ := openStore(t, "b1")
	put(t, s, "b1", "k", strings.Repeat("0", 4096))
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 1; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			body := strings.NewReader(strings.Repeat(fmt.Sprint(i%10), 4096+i%7))
			if _, err := s.PutObject(context.Background(), "b1", "k", body, storage.ObjectMeta{}, true); err != nil {
				t.Error(err)
				return
			}
		}
	})
	for range 300 {
		rc, obj, err := s.OpenObject(context.Background(), "b1", "k", nil)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		closeOrFail(t, rc)
		if err != nil {
			t.Fatal(err)
		}
		if md5.Sum(data) != obj.MD5 || int64(len(data)) != obj.Size {
			t.Fatalf("read %d bytes that do not match metadata of size %d", len(data), obj.Size)
		}
	}
	close(done)
	wg.Wait()
}

// TestOverwriteBetweenMetaReadAndOpen forces a writer into the window between a reader's
// metadata read and its open: the writer must wait until the reader holds its handle.
func TestOverwriteBetweenMetaReadAndOpen(t *testing.T) {
	s, _ := openStore(t, "b1")
	put(t, s, "b1", "k", "old")
	written := make(chan struct{})
	original := afterMetaRead
	t.Cleanup(func() { afterMetaRead = original })
	var once sync.Once
	afterMetaRead = func() {
		once.Do(func() {
			go func() {
				defer close(written)
				if _, err := s.PutObject(context.Background(), "b1", "k", strings.NewReader("new"), storage.ObjectMeta{}, true); err != nil {
					t.Error(err)
				}
			}()
			time.Sleep(50 * time.Millisecond) // the writer is now blocked on the key lock
		})
	}
	if got := read(t, s, "b1", "k", nil); got != "old" {
		t.Fatalf("reader got %q, want old", got)
	}
	<-written
	afterMetaRead = original
	if got := read(t, s, "b1", "k", nil); got != "new" {
		t.Fatalf("later read got %q, want new", got)
	}
}

func TestDeleteWhileReading(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot delete an open file")
	}
	s, _ := openStore(t, "b1")
	put(t, s, "b1", "k", "still readable")
	rc, _, err := s.OpenObject(context.Background(), "b1", "k", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closeOrFail(t, rc)
	if err := s.DeleteObject(context.Background(), "b1", "k"); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(rc)
	if err != nil || string(data) != "still readable" {
		t.Fatalf("read = %q, %v", data, err)
	}
	if _, err := s.StatObject(context.Background(), "b1", "k"); !errors.Is(err, storage.ErrObjectNotFound) {
		t.Fatalf("stat err = %v", err)
	}
}

func TestRange(t *testing.T) {
	s, _ := openStore(t, "b1")
	put(t, s, "b1", "k", "0123456789")
	if got := read(t, s, "b1", "k", &storage.ByteRange{Start: 2, End: 4}); got != "234" {
		t.Fatalf("range = %q", got)
	}
}

func TestCopyAcrossBuckets(t *testing.T) {
	s, _ := openStore(t, "b1", "b2")
	src := put(t, s, "b1", "src", "payload")
	dst, err := s.CopyObject(context.Background(), "b1", "src", "b2", "dst", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if dst.MD5 != src.MD5 || dst.ContentType != src.ContentType {
		t.Fatalf("copy = %+v, source = %+v", dst, src)
	}
	put(t, s, "b1", "src", "changed")
	if got := read(t, s, "b2", "dst", nil); got != "payload" {
		t.Fatalf("copy changed with its source: %q", got)
	}
}

func TestDeleteMissingObject(t *testing.T) {
	s, _ := openStore(t, "b1")
	if err := s.DeleteObject(context.Background(), "b1", "nope"); !errors.Is(err, storage.ErrObjectNotFound) {
		t.Fatalf("err = %v, want ErrObjectNotFound", err)
	}
}

func TestListPages(t *testing.T) {
	s, _ := openStore(t, "b1")
	for i := range 250 {
		put(t, s, "b1", fmt.Sprintf("k%03d", i), "x")
	}
	var keys []string
	from, pages := "", 0
	for {
		page, err := s.ListObjects(context.Background(), "b1", storage.ListOptions{StartFrom: from, MaxKeys: 100})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, o := range page.Objects {
			keys = append(keys, o.Key)
		}
		if !page.IsTruncated {
			break
		}
		from = page.NextFrom
	}
	if pages != 3 || len(keys) != 250 {
		t.Fatalf("pages = %d, keys = %d", pages, len(keys))
	}
	for i, k := range keys {
		if k != fmt.Sprintf("k%03d", i) {
			t.Fatalf("keys[%d] = %s", i, k)
		}
	}
}

func TestStartupSweep(t *testing.T) {
	s, root := openStore(t, "b1")
	put(t, s, "b1", "k", "kept")
	orphan := filepath.Join(filepath.Dir(dataFiles(t, root, "b1")[0]), hashKey("k")+".orphan")
	if err := os.WriteFile(orphan, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, tmpDir, "write-leftover"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan data file survived: %v", err)
	}
	if entries := tmpEntries(t, root); len(entries) != 0 {
		t.Fatalf(".tmp holds %d entries", len(entries))
	}
	if got := read(t, s, "b1", "k", nil); got != "kept" {
		t.Fatalf("read = %q", got)
	}
}

func TestDeleteNonEmptyBucket(t *testing.T) {
	s, _ := openStore(t, "b1")
	put(t, s, "b1", "k", "x")
	if err := s.DeleteBucket(context.Background(), "b1"); !errors.Is(err, storage.ErrBucketNotEmpty) {
		t.Fatalf("err = %v, want ErrBucketNotEmpty", err)
	}
}

func TestEmptyObject(t *testing.T) {
	s, _ := openStore(t, "b1")
	obj, err := s.PutObject(context.Background(), "b1", "empty", bytes.NewReader(nil), storage.ObjectMeta{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if obj.Size != 0 || obj.MD5 != md5.Sum(nil) {
		t.Fatalf("obj = %+v", obj)
	}
	if got := read(t, s, "b1", "empty", nil); got != "" {
		t.Fatalf("read = %q", got)
	}
}
