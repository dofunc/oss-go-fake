// Package service holds the object semantics every protocol shares: name rules, ACL decisions,
// listing with delimiters and pagination, and the mapping of storage failures to typed errors.
package service

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dofunc/oss-go-fake/internal/storage"
)

type Kind int

const (
	KindInvalidBucketName Kind = iota + 1
	KindInvalidObjectName
	KindInvalidArgument
	KindNoSuchBucket
	KindNoSuchKey
	KindBucketAlreadyExists
	KindBucketNotEmpty
	KindObjectAlreadyExists
	KindAccessDenied
	KindInvalidRange
)

// Error is what the service returns for every failure a client caused. Protocols map Kind to
// their own status codes and error codes.
type Error struct {
	Kind    Kind
	Message string
}

func (e *Error) Error() string { return e.Message }

// KindOf returns the Kind of err, or 0 when err is not a service error.
func KindOf(err error) Kind {
	var se *Error
	if errors.As(err, &se) {
		return se.Kind
	}
	return 0
}

// Service holds the protocol-neutral object semantics shared by every protocol.
type Service struct {
	store storage.Storage
}

func New(store storage.Storage) *Service {
	return &Service{store: store}
}

const (
	defaultMaxKeys = 100
	maxMaxKeys     = 1000
	listBatch      = 1000
	// afterPrefix sorts after every valid UTF-8 continuation of a prefix: 0xFF never occurs in
	// UTF-8, so prefix+afterPrefix skips every key that starts with prefix.
	afterPrefix = "\xff"
)

var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

func ValidateBucketName(name string) error {
	if !bucketName.MatchString(name) {
		return &Error{Kind: KindInvalidBucketName, Message: "The specified bucket is not valid."}
	}
	return nil
}

func ValidateKey(key string) error {
	if len(key) == 0 || len(key) > 1023 || !utf8.ValidString(key) ||
		strings.HasPrefix(key, "/") || strings.HasPrefix(key, `\`) {
		return &Error{Kind: KindInvalidObjectName, Message: "The specified object is not valid."}
	}
	return nil
}

type Operation int

const (
	OpGetObject Operation = iota + 1
	OpHeadObject
	OpGetObjectMeta
	OpListObjects
	OpGetBucketInfo
	OpWrite // every bucket or object mutation
)

// Allowed reports whether a request may perform op on b. Authenticated callers always may: the
// fake has a single tenant, every configured key owns every bucket. Anonymous callers get object
// reads on a public-read bucket and nothing else -- public-read never lets them list the bucket.
// CORS preflight never reaches here: it is judged by the bucket's CORS rules alone.
func Allowed(b storage.Bucket, op Operation, authenticated bool) bool {
	if authenticated {
		return true
	}
	return b.ACL == storage.ACLPublicRead &&
		(op == OpGetObject || op == OpHeadObject || op == OpGetObjectMeta)
}

func (s *Service) PutBucket(ctx context.Context, name string, acl storage.ACL) error {
	if err := ValidateBucketName(name); err != nil {
		return err
	}
	return mapErr(s.store.CreateBucket(ctx, storage.Bucket{Name: name, ACL: acl, CreatedAt: time.Now().UTC()}))
}

// EnsureBucket creates a bucket declared in the configuration, or applies the configured ACL to
// an existing one. It runs at startup only.
func (s *Service) EnsureBucket(ctx context.Context, name string, acl storage.ACL) error {
	if err := ValidateBucketName(name); err != nil {
		return err
	}
	b, err := s.store.GetBucket(ctx, name)
	if errors.Is(err, storage.ErrBucketNotFound) {
		return mapErr(s.store.CreateBucket(ctx, storage.Bucket{Name: name, ACL: acl, CreatedAt: time.Now().UTC()}))
	}
	if err != nil {
		return err
	}
	b.ACL = acl
	return mapErr(s.store.UpdateBucket(ctx, b))
}

func (s *Service) DeleteBucket(ctx context.Context, name string) error {
	return mapErr(s.store.DeleteBucket(ctx, name))
}

func (s *Service) GetBucket(ctx context.Context, name string) (storage.Bucket, error) {
	b, err := s.store.GetBucket(ctx, name)
	return b, mapErr(err)
}

func (s *Service) ListBuckets(ctx context.Context) ([]storage.Bucket, error) {
	buckets, err := s.store.ListBuckets(ctx)
	return buckets, mapErr(err)
}

func (s *Service) Put(ctx context.Context, bucket, key string, body io.Reader, meta storage.ObjectMeta, overwrite bool) (storage.Object, error) {
	if err := ValidateKey(key); err != nil {
		return storage.Object{}, err
	}
	obj, err := s.store.PutObject(ctx, bucket, key, body, meta, overwrite)
	return obj, mapErr(err)
}

func (s *Service) Head(ctx context.Context, bucket, key string) (storage.Object, error) {
	if err := ValidateKey(key); err != nil {
		return storage.Object{}, err
	}
	obj, err := s.store.StatObject(ctx, bucket, key)
	return obj, mapErr(err)
}

// Get opens an object. rangeOf turns the object size into the byte range to read (nil for the
// whole object); it runs against the size of the very object that gets opened, so a concurrent
// overwrite with a different size cannot pair a stale range with new content.
func (s *Service) Get(ctx context.Context, bucket, key string, rangeOf func(size int64) (*storage.ByteRange, error)) (io.ReadCloser, storage.Object, *storage.ByteRange, error) {
	if err := ValidateKey(key); err != nil {
		return nil, storage.Object{}, nil, err
	}
	for attempt := 0; ; attempt++ {
		stat, err := s.store.StatObject(ctx, bucket, key)
		if err != nil {
			return nil, storage.Object{}, nil, mapErr(err)
		}
		rng, err := rangeOf(stat.Size)
		if err != nil {
			return nil, storage.Object{}, nil, err
		}
		rc, obj, err := s.store.OpenObject(ctx, bucket, key, rng)
		if err != nil {
			return nil, storage.Object{}, nil, mapErr(err)
		}
		if obj.Size == stat.Size || attempt == 2 {
			return rc, obj, rng, nil
		}
		if err := rc.Close(); err != nil {
			return nil, storage.Object{}, nil, err
		}
	}
}

func (s *Service) Copy(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string, meta *storage.ObjectMeta, overwrite bool) (storage.Object, error) {
	if err := ValidateKey(srcKey); err != nil {
		return storage.Object{}, err
	}
	if err := ValidateKey(dstKey); err != nil {
		return storage.Object{}, err
	}
	obj, err := s.store.CopyObject(ctx, srcBucket, srcKey, dstBucket, dstKey, meta, overwrite)
	return obj, mapErr(err)
}

// Delete removes an object. A missing object is not an error, as in OSS.
func (s *Service) Delete(ctx context.Context, bucket, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	err := s.store.DeleteObject(ctx, bucket, key)
	if errors.Is(err, storage.ErrObjectNotFound) {
		return nil
	}
	return mapErr(err)
}

// DeleteMany removes every key and returns the keys reported as deleted, missing ones included.
func (s *Service) DeleteMany(ctx context.Context, bucket string, keys []string) ([]string, error) {
	if _, err := s.store.GetBucket(ctx, bucket); err != nil {
		return nil, mapErr(err)
	}
	deleted := make([]string, 0, len(keys))
	for _, key := range keys {
		if err := s.Delete(ctx, bucket, key); err != nil {
			return deleted, err
		}
		deleted = append(deleted, key)
	}
	return deleted, nil
}

// ListQuery carries the raw listing parameters of a request.
type ListQuery struct {
	Prefix    string
	Delimiter string
	StartFrom string // marker or start-after
	Token     string // continuation token; takes precedence over StartFrom when set
	MaxKeys   string // raw value, empty means the default
}

type ListResult struct {
	Objects        []storage.Object
	CommonPrefixes []string
	IsTruncated    bool
	NextMarker     string // last object key or common prefix returned, set when truncated
	NextToken      string // NextMarker as a continuation token
}

// List returns one page of a bucket. With a delimiter, keys that share a prefix segment fold
// into one common prefix, and max-keys counts objects and common prefixes together.
func (s *Service) List(ctx context.Context, bucket string, q ListQuery) (ListResult, error) {
	maxKeys := defaultMaxKeys
	if q.MaxKeys != "" {
		n, err := strconv.Atoi(q.MaxKeys)
		if err != nil || n < 1 || n > maxMaxKeys {
			return ListResult{}, &Error{Kind: KindInvalidArgument, Message: "max-keys must be between 1 and 1000."}
		}
		maxKeys = n
	}
	start := q.StartFrom
	if q.Token != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(q.Token)
		if err != nil || !utf8.Valid(decoded) {
			return ListResult{}, &Error{Kind: KindInvalidArgument, Message: "The continuation token is not valid."}
		}
		start = string(decoded)
	}

	var res ListResult
	count, from, last := 0, start, ""
	for {
		page, err := s.store.ListObjects(ctx, bucket, storage.ListOptions{Prefix: q.Prefix, StartFrom: from, MaxKeys: listBatch})
		if err != nil {
			return ListResult{}, mapErr(err)
		}
		skipped := false
		for _, obj := range page.Objects {
			item, isPrefix := obj.Key, false
			if q.Delimiter != "" {
				if i := strings.Index(obj.Key[len(q.Prefix):], q.Delimiter); i >= 0 {
					item, isPrefix = obj.Key[:len(q.Prefix)+i+len(q.Delimiter)], true
				}
			}
			// A common prefix at or before the start point was returned by an earlier page.
			if !isPrefix || item > start {
				if count == maxKeys {
					res.IsTruncated = true
					res.NextMarker = last
					res.NextToken = base64.RawURLEncoding.EncodeToString([]byte(last))
					return res, nil
				}
				if isPrefix {
					res.CommonPrefixes = append(res.CommonPrefixes, item)
				} else {
					res.Objects = append(res.Objects, obj)
				}
				count++
				last = item
			}
			if isPrefix {
				from = item + afterPrefix
				skipped = true
				break
			}
			from = obj.Key
		}
		if !skipped && !page.IsTruncated {
			return res, nil
		}
	}
}

// mapErr turns storage errors into service errors and passes anything else through.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, storage.ErrBucketNotFound):
		return &Error{Kind: KindNoSuchBucket, Message: "The specified bucket does not exist."}
	case errors.Is(err, storage.ErrObjectNotFound):
		return &Error{Kind: KindNoSuchKey, Message: "The specified key does not exist."}
	case errors.Is(err, storage.ErrBucketExists):
		return &Error{Kind: KindBucketAlreadyExists, Message: "The requested bucket name is not available."}
	case errors.Is(err, storage.ErrBucketNotEmpty):
		return &Error{Kind: KindBucketNotEmpty, Message: "The bucket you tried to delete is not empty."}
	case errors.Is(err, storage.ErrObjectExists):
		return &Error{Kind: KindObjectAlreadyExists, Message: "The object you specified already exists and can not be overwritten."}
	}
	return err
}
