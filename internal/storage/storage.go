// Package storage defines how buckets and objects are persisted. Implementations know nothing
// about protocols, signatures or permissions.
package storage

import (
	"context"
	"errors"
	"io"
	"time"
)

// ObjectMeta is what a writer supplies; Object adds what the store derives.
type ObjectMeta struct {
	ContentType string
	UserMeta    map[string]string // keys without the x-oss-meta- prefix, lower case
}

type Object struct {
	Bucket       string
	Key          string
	Size         int64
	MD5          [16]byte
	LastModified time.Time
	ObjectMeta
}

type Bucket struct {
	Name      string
	ACL       ACL
	CreatedAt time.Time
}

type ACL string

const (
	ACLPrivate    ACL = "private"
	ACLPublicRead ACL = "public-read"
)

// ByteRange is inclusive on both ends, already validated against the object size.
type ByteRange struct{ Start, End int64 }

type ListOptions struct {
	Prefix    string
	StartFrom string // exclusive: marker, start-after or a decoded continuation token
	MaxKeys   int
}

type ListPage struct {
	Objects     []Object
	IsTruncated bool
	NextFrom    string // last key returned when truncated
}

var (
	ErrBucketNotFound = errors.New("bucket not found")
	ErrBucketExists   = errors.New("bucket already exists")
	ErrBucketNotEmpty = errors.New("bucket not empty")
	ErrObjectNotFound = errors.New("object not found")
	ErrObjectExists   = errors.New("object already exists")
)

// Storage persists buckets and objects. It knows nothing about protocols or permissions.
// Every method is safe for concurrent use. A single object write is atomic: readers see
// either the old object or the new one, never a mix.
type Storage interface {
	CreateBucket(ctx context.Context, b Bucket) error
	UpdateBucket(ctx context.Context, b Bucket) error
	GetBucket(ctx context.Context, name string) (Bucket, error)
	ListBuckets(ctx context.Context) ([]Bucket, error)
	DeleteBucket(ctx context.Context, name string) error

	PutObject(ctx context.Context, bucket, key string, body io.Reader, meta ObjectMeta, overwrite bool) (Object, error)
	StatObject(ctx context.Context, bucket, key string) (Object, error)
	// OpenObject returns a reader limited to rng, or the whole object when rng is nil.
	OpenObject(ctx context.Context, bucket, key string, rng *ByteRange) (io.ReadCloser, Object, error)
	// CopyObject keeps the source MD5. meta nil means copy the source metadata.
	CopyObject(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string, meta *ObjectMeta, overwrite bool) (Object, error)
	DeleteObject(ctx context.Context, bucket, key string) error
	ListObjects(ctx context.Context, bucket string, opt ListOptions) (ListPage, error)
}
