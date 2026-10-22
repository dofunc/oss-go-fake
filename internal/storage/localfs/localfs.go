// Package localfs stores buckets and objects in a local directory.
//
// Object names never become file paths: an object lives under the SHA-256 of its name, so "a"
// and "a/b" coexist, names up to 1023 bytes fit, and case-insensitive file systems keep "A" and
// "a" apart. Each object is a metadata JSON file plus a data file whose name changes on every
// write. Replacing the metadata file is the commit point of a write.
package localfs

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dofunc/oss-go-fake/internal/storage"
)

const (
	tmpDir      = ".tmp"
	objectsDir  = "objects"
	bucketFile  = "bucket.json"
	metaSuffix  = ".json"
	tempPattern = "write-*"
)

// afterMetaRead runs between reading an object's metadata and opening its data file. Tests in
// this package replace it to force a write into that window; it does nothing otherwise.
var afterMetaRead = func() {}

// Store is a storage.Storage backed by a directory.
type Store struct {
	root  string
	locks *keyLocks
	// buckets guards bucket creation and removal against object writes: object operations hold
	// it shared, DeleteBucket holds it exclusively so no write lands in a bucket being removed.
	buckets sync.RWMutex
}

var _ storage.Storage = (*Store)(nil)

type bucketRecord struct {
	Name      string      `json:"name"`
	ACL       storage.ACL `json:"acl"`
	CreatedAt time.Time   `json:"createdAt"`
}

type metaRecord struct {
	Key          string            `json:"key"`
	Size         int64             `json:"size"`
	ETag         string            `json:"etag"` // upper-case hex MD5, no quotes
	ContentType  string            `json:"contentType"`
	Meta         map[string]string `json:"meta,omitempty"`
	LastModified time.Time         `json:"lastModified"`
	Data         string            `json:"data"` // data file name, next to the metadata file
}

// Open prepares root and sweeps what an interrupted run left behind: everything in .tmp/ and
// every data file no metadata refers to.
func Open(root string) (*Store, error) {
	s := &Store{root: root, locks: newKeyLocks()}
	if err := os.RemoveAll(filepath.Join(root, tmpDir)); err != nil {
		return nil, fmt.Errorf("clear temp dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(root, tmpDir), 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	if err := s.sweep(); err != nil {
		return nil, fmt.Errorf("sweep data dir: %w", err)
	}
	return s, nil
}

// sweep removes data files that no metadata file names.
func (s *Store) sweep() error {
	buckets, err := s.ListBuckets(context.Background())
	if err != nil {
		return err
	}
	for _, b := range buckets {
		dirs, err := os.ReadDir(filepath.Join(s.root, b.Name, objectsDir))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, d := range dirs {
			if err := s.sweepDir(filepath.Join(s.root, b.Name, objectsDir, d.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) sweepDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	referenced := make(map[string]bool)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), metaSuffix) {
			continue
		}
		m, err := readMetaFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		referenced[m.Data] = true
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), metaSuffix) || referenced[e.Name()] {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			slog.Warn("remove orphan data file failed", "path", filepath.Join(dir, e.Name()), "err", err)
		}
	}
	return nil
}

func (s *Store) CreateBucket(_ context.Context, b storage.Bucket) error {
	s.buckets.Lock()
	defer s.buckets.Unlock()
	if _, err := os.Stat(s.bucketPath(b.Name)); err == nil {
		return storage.ErrBucketExists
	}
	if err := os.MkdirAll(filepath.Join(s.root, b.Name, objectsDir), 0o755); err != nil {
		return err
	}
	return s.writeBucket(b)
}

func (s *Store) UpdateBucket(_ context.Context, b storage.Bucket) error {
	s.buckets.Lock()
	defer s.buckets.Unlock()
	if _, err := os.Stat(s.bucketPath(b.Name)); err != nil {
		return storage.ErrBucketNotFound
	}
	return s.writeBucket(b)
}

func (s *Store) writeBucket(b storage.Bucket) error {
	data, err := json.Marshal(bucketRecord{Name: b.Name, ACL: b.ACL, CreatedAt: b.CreatedAt.UTC()})
	if err != nil {
		return err
	}
	return s.replaceFile(s.bucketPath(b.Name), data)
}

func (s *Store) GetBucket(_ context.Context, name string) (storage.Bucket, error) {
	data, err := os.ReadFile(s.bucketPath(name))
	if errors.Is(err, fs.ErrNotExist) {
		return storage.Bucket{}, storage.ErrBucketNotFound
	}
	if err != nil {
		return storage.Bucket{}, err
	}
	var r bucketRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return storage.Bucket{}, fmt.Errorf("decode %s: %w", s.bucketPath(name), err)
	}
	return storage.Bucket{Name: r.Name, ACL: r.ACL, CreatedAt: r.CreatedAt}, nil
}

func (s *Store) ListBuckets(ctx context.Context) ([]storage.Bucket, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	var buckets []storage.Bucket
	for _, e := range entries {
		if !e.IsDir() || e.Name() == tmpDir {
			continue
		}
		b, err := s.GetBucket(ctx, e.Name())
		if errors.Is(err, storage.ErrBucketNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		buckets = append(buckets, b)
	}
	return buckets, nil
}

func (s *Store) DeleteBucket(_ context.Context, name string) error {
	s.buckets.Lock()
	defer s.buckets.Unlock()
	if _, err := os.Stat(s.bucketPath(name)); err != nil {
		return storage.ErrBucketNotFound
	}
	empty := true
	err := filepath.WalkDir(filepath.Join(s.root, name, objectsDir), func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), metaSuffix) {
			empty = false
			return fs.SkipAll
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if !empty {
		return storage.ErrBucketNotEmpty
	}
	return os.RemoveAll(filepath.Join(s.root, name))
}

func (s *Store) PutObject(ctx context.Context, bucket, key string, body io.Reader, meta storage.ObjectMeta, overwrite bool) (storage.Object, error) {
	s.buckets.RLock()
	defer s.buckets.RUnlock()
	if _, err := s.GetBucket(ctx, bucket); err != nil {
		return storage.Object{}, err
	}
	unlock := s.locks.lock(bucket + "\x00" + key)
	defer unlock()
	return s.putLocked(bucket, key, body, meta, overwrite)
}

// putLocked writes an object; the caller holds the key's write lock and the bucket lock shared.
func (s *Store) putLocked(bucket, key string, body io.Reader, meta storage.ObjectMeta, overwrite bool) (storage.Object, error) {
	old, err := s.readMeta(bucket, key)
	switch {
	case err == nil && !overwrite:
		return storage.Object{}, storage.ErrObjectExists
	case err != nil && !errors.Is(err, storage.ErrObjectNotFound):
		return storage.Object{}, err
	}

	tmp, err := os.CreateTemp(filepath.Join(s.root, tmpDir), tempPattern)
	if err != nil {
		return storage.Object{}, err
	}
	tmpName := tmp.Name()
	hasher := md5.New()
	size, err := io.Copy(io.MultiWriter(tmp, hasher), body)
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		removeQuietly(tmpName)
		return storage.Object{}, err
	}

	sum := hashKey(key)
	dir := s.objectDir(bucket, sum)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		removeQuietly(tmpName)
		return storage.Object{}, err
	}
	dataName := sum + "." + randomID()
	if err := os.Rename(tmpName, filepath.Join(dir, dataName)); err != nil {
		removeQuietly(tmpName)
		return storage.Object{}, err
	}

	var digest [16]byte
	copy(digest[:], hasher.Sum(nil))
	record := metaRecord{
		Key:          key,
		Size:         size,
		ETag:         strings.ToUpper(hex.EncodeToString(digest[:])),
		ContentType:  meta.ContentType,
		Meta:         meta.UserMeta,
		LastModified: time.Now().UTC().Truncate(time.Second),
		Data:         dataName,
	}
	encoded, err := json.Marshal(record)
	if err == nil {
		err = s.replaceFile(filepath.Join(dir, sum+metaSuffix), encoded)
	}
	if err != nil {
		removeQuietly(filepath.Join(dir, dataName))
		return storage.Object{}, err
	}

	if old.Data != "" {
		if err := os.Remove(filepath.Join(dir, old.Data)); err != nil {
			slog.Warn("remove replaced data file failed", "bucket", bucket, "key", key, "err", err)
		}
	}
	return record.object(bucket), nil
}

func (s *Store) StatObject(_ context.Context, bucket, key string) (storage.Object, error) {
	runlock := s.locks.rlock(bucket + "\x00" + key)
	defer runlock()
	m, err := s.readMeta(bucket, key)
	if err != nil {
		return storage.Object{}, err
	}
	return m.object(bucket), nil
}

func (s *Store) OpenObject(_ context.Context, bucket, key string, rng *storage.ByteRange) (io.ReadCloser, storage.Object, error) {
	runlock := s.locks.rlock(bucket + "\x00" + key)
	meta, err := s.readMeta(bucket, key)
	if err != nil {
		runlock()
		return nil, storage.Object{}, err
	}
	afterMetaRead()
	f, err := os.Open(filepath.Join(s.objectDir(bucket, hashKey(key)), meta.Data))
	runlock() // the handle keeps the bytes readable even if a later write deletes the file
	if err != nil {
		return nil, storage.Object{}, err
	}
	if rng == nil {
		return f, meta.object(bucket), nil
	}
	if _, err := f.Seek(rng.Start, io.SeekStart); err != nil {
		closeQuietly(f)
		return nil, storage.Object{}, err
	}
	return limitedFile{Reader: io.LimitReader(f, rng.End-rng.Start+1), f: f}, meta.object(bucket), nil
}

func (s *Store) CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string, meta *storage.ObjectMeta, overwrite bool) (storage.Object, error) {
	// The source is opened and its lock released before the destination lock is taken, so two
	// copies in opposite directions cannot deadlock. The open handle pins the source content.
	src, srcObj, err := s.OpenObject(ctx, srcBucket, srcKey, nil)
	if err != nil {
		return storage.Object{}, err
	}
	defer closeQuietly(src)
	if meta == nil {
		meta = &srcObj.ObjectMeta
	}
	return s.PutObject(ctx, dstBucket, dstKey, src, *meta, overwrite)
}

func (s *Store) DeleteObject(_ context.Context, bucket, key string) error {
	s.buckets.RLock()
	defer s.buckets.RUnlock()
	if _, err := os.Stat(s.bucketPath(bucket)); err != nil {
		return storage.ErrBucketNotFound
	}
	unlock := s.locks.lock(bucket + "\x00" + key)
	defer unlock()
	m, err := s.readMeta(bucket, key)
	if err != nil {
		return err
	}
	dir := s.objectDir(bucket, hashKey(key))
	if err := os.Remove(filepath.Join(dir, hashKey(key)+metaSuffix)); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(dir, m.Data)); err != nil {
		slog.Warn("remove deleted data file failed", "bucket", bucket, "key", key, "err", err)
	}
	return nil
}

// ListObjects reads every metadata file of the bucket, so its cost grows with the object count.
// Metadata files are replaced by rename, which makes each read a consistent snapshot of one object.
func (s *Store) ListObjects(ctx context.Context, bucket string, opt storage.ListOptions) (storage.ListPage, error) {
	if _, err := s.GetBucket(ctx, bucket); err != nil {
		return storage.ListPage{}, err
	}
	var all []storage.Object
	err := filepath.WalkDir(filepath.Join(s.root, bucket, objectsDir), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), metaSuffix) {
			return nil
		}
		m, err := readMetaFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil // deleted while walking
		}
		if err != nil {
			return err
		}
		if strings.HasPrefix(m.Key, opt.Prefix) && m.Key > opt.StartFrom {
			all = append(all, m.object(bucket))
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return storage.ListPage{}, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Key < all[j].Key })

	page := storage.ListPage{Objects: all}
	if opt.MaxKeys > 0 && len(all) > opt.MaxKeys {
		page.Objects = all[:opt.MaxKeys]
		page.IsTruncated = true
		page.NextFrom = page.Objects[len(page.Objects)-1].Key
	}
	return page, nil
}

func (s *Store) readMeta(bucket, key string) (metaRecord, error) {
	sum := hashKey(key)
	m, err := readMetaFile(filepath.Join(s.objectDir(bucket, sum), sum+metaSuffix))
	if errors.Is(err, fs.ErrNotExist) {
		return metaRecord{}, storage.ErrObjectNotFound
	}
	return m, err
}

func readMetaFile(path string) (metaRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return metaRecord{}, err
	}
	var m metaRecord
	if err := json.Unmarshal(data, &m); err != nil {
		return metaRecord{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return m, nil
}

// replaceFile writes data to a temp file and renames it over path, so readers see the old or
// the new content and never a partial one.
func (s *Store) replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Join(s.root, tmpDir), tempPattern)
	if err != nil {
		return err
	}
	_, err = io.Copy(tmp, bytes.NewReader(data))
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		removeQuietly(tmp.Name())
	}
	return err
}

func (s *Store) bucketPath(name string) string {
	return filepath.Join(s.root, name, bucketFile)
}

func (s *Store) objectDir(bucket, sum string) string {
	return filepath.Join(s.root, bucket, objectsDir, sum[:2])
}

func (m metaRecord) object(bucket string) storage.Object {
	var digest [16]byte
	if _, err := hex.Decode(digest[:], []byte(m.ETag)); err != nil {
		slog.Warn("metadata carries a malformed etag", "bucket", bucket, "key", m.Key, "etag", m.ETag)
	}
	return storage.Object{
		Bucket:       bucket,
		Key:          m.Key,
		Size:         m.Size,
		MD5:          digest,
		LastModified: m.LastModified,
		ObjectMeta:   storage.ObjectMeta{ContentType: m.ContentType, UserMeta: m.Meta},
	}
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b[:])
}

func removeQuietly(path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("remove temp file failed", "path", path, "err", err)
	}
}

func closeQuietly(c io.Closer) {
	if err := c.Close(); err != nil {
		slog.Warn("close file failed", "err", err)
	}
}

type limitedFile struct {
	io.Reader
	f *os.File
}

func (l limitedFile) Close() error { return l.f.Close() }
