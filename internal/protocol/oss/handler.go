// Package oss speaks the Alibaba Cloud OSS REST protocol on top of the service layer.
package oss

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dofunc/oss-go-fake/internal/config"
	"github.com/dofunc/oss-go-fake/internal/protocol"
	"github.com/dofunc/oss-go-fake/internal/service"
	"github.com/dofunc/oss-go-fake/internal/storage"
)

const (
	headerRequestID  = "x-oss-request-id"
	userMetaPrefix   = "x-oss-meta-"
	maxDeleteObjects = 1000
	maxDeleteBody    = 2 << 20
)

// unsupportedSubResources are OSS sub-resources this fake does not implement. A request naming
// one gets 501 NotImplemented instead of being mistaken for a plain object or bucket request.
var unsupportedSubResources = map[string]bool{
	"acl": true, "uploads": true, "uploadId": true, "partNumber": true, "location": true,
	"cors": true, "logging": true, "website": true, "referer": true, "lifecycle": true,
	"append": true, "position": true, "tagging": true, "stat": true, "restore": true,
	"callback": true, "versions": true, "versioning": true, "versionId": true,
	"sequential": true, "symlink": true, "regionList": true, "cloudboxes": true,
	"x-oss-process": true, "x-oss-async-process": true, "policy": true, "encryption": true,
	"replication": true, "worm": true, "wormId": true, "inventory": true, "qos": true,
	"requestPayment": true, "transferAcceleration": true, "accessPoint": true, "cname": true,
	"img": true, "style": true, "live": true, "vod": true, "tags": true, "metaQuery": true,
	"accessmonitor": true, "resourceGroup": true, "httpsConfig": true, "publicAccessBlock": true,
	"overwriteConfig": true, "seal": true, "select": true, "cleanRestoredObject": true,
	"bucketArchiveDirectRead": true, "metadataConfiguration": true,
}

// responseOverrides are the query parameters that override GetObject response headers.
var responseOverrides = map[string]string{
	"response-content-type":        "Content-Type",
	"response-content-language":    "Content-Language",
	"response-expires":             "Expires",
	"response-cache-control":       "Cache-Control",
	"response-content-disposition": "Content-Disposition",
	"response-content-encoding":    "Content-Encoding",
}

type Options struct {
	Domain     string                       // base domain of virtual-hosted requests, empty for path-style only
	Region     string                       // region V4 credential scopes must name
	AccessKeys map[string]string            // access key id -> secret
	CORS       map[string][]config.CORSRule // bucket name -> rules
	Now        func() time.Time             // clock, time.Now when nil
}

// Handler serves the OSS protocol.
type Handler struct {
	svc    *service.Service
	auth   *Authenticator
	domain string
	region string
	cors   map[string][]config.CORSRule
}

var _ protocol.Protocol = (*Handler)(nil)

func New(svc *service.Service, opt Options) *Handler {
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	return &Handler{
		svc:    svc,
		auth:   NewAuthenticator(opt.AccessKeys, opt.Region, now),
		domain: strings.ToLower(opt.Domain),
		region: opt.Region,
		cors:   opt.CORS,
	}
}

func (h *Handler) Name() string { return "OSS" }

func (h *Handler) Claims(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	q := r.URL.Query()
	return strings.HasPrefix(auth, "OSS ") || strings.HasPrefix(auth, v4Algorithm+" ") ||
		q.Has("OSSAccessKeyId") || q.Has("x-oss-signature-version")
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bucket, key := parseAddress(r, h.domain)
	if err := h.serve(w, r, bucket, key); err != nil {
		writeError(w, r, err)
	}
}

type route struct {
	op         service.Operation
	bucketless bool // ListBuckets and PutBucket: no bucket record to check
	serve      func(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, key string) error
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request, bucket, key string) error {
	ctx := r.Context()
	if bucket != "" {
		if err := service.ValidateBucketName(bucket); err != nil {
			return err
		}
	}
	if r.Method == http.MethodOptions {
		return h.preflight(ctx, w, r, bucket)
	}
	rt, err := h.route(r, bucket, key)
	if err != nil {
		return err
	}
	authenticated, err := h.auth.Verify(r, bucket, key)
	if err != nil {
		return err
	}
	var b storage.Bucket
	if !rt.bucketless {
		if b, err = h.svc.GetBucket(ctx, bucket); err != nil {
			return err
		}
		applyCORS(w, r, h.cors[bucket])
	}
	if err := authorize(rt, b, authenticated); err != nil {
		return err
	}
	return rt.serve(ctx, w, r, bucket, key)
}

// route picks the operation from the method, the presence of a bucket and key, and the
// sub-resource in the query.
func (h *Handler) route(r *http.Request, bucket, key string) (route, error) {
	q := r.URL.Query()
	for name := range q {
		if unsupportedSubResources[name] {
			return route{}, notImplemented("Sub-resource " + name)
		}
	}
	m := r.Method
	switch {
	case bucket == "" && m == http.MethodGet:
		return route{bucketless: true, serve: h.listBuckets}, nil
	case bucket == "":
		return route{}, notImplemented(m + " on the service")
	case key == "" && m == http.MethodPut:
		return route{bucketless: true, serve: h.putBucket}, nil
	case key == "" && m == http.MethodDelete:
		return route{op: service.OpWrite, serve: h.deleteBucket}, nil
	case key == "" && m == http.MethodGet && q.Has("bucketInfo"):
		return route{op: service.OpGetBucketInfo, serve: h.getBucketInfo}, nil
	case key == "" && m == http.MethodGet && q.Get("list-type") == "2":
		return route{op: service.OpListObjects, serve: h.listObjectsV2}, nil
	case key == "" && m == http.MethodGet:
		return route{op: service.OpListObjects, serve: h.listObjects}, nil
	case key == "" && m == http.MethodPost && q.Has("delete"):
		return route{op: service.OpWrite, serve: h.deleteMultipleObjects}, nil
	case key == "":
		return route{}, notImplemented(m + " on a bucket")
	case m == http.MethodPut && r.Header.Get("x-oss-copy-source") != "":
		return route{op: service.OpWrite, serve: h.copyObject}, nil
	case m == http.MethodPut:
		return route{op: service.OpWrite, serve: h.putObject}, nil
	case (m == http.MethodHead || m == http.MethodGet) && q.Has("objectMeta"):
		return route{op: service.OpGetObjectMeta, serve: h.getObjectMeta}, nil
	case m == http.MethodHead:
		return route{op: service.OpHeadObject, serve: h.headObject}, nil
	case m == http.MethodGet:
		return route{op: service.OpGetObject, serve: h.getObject}, nil
	case m == http.MethodDelete:
		return route{op: service.OpWrite, serve: h.deleteObject}, nil
	}
	return route{}, notImplemented(m + " on an object")
}

func (h *Handler) listBuckets(ctx context.Context, w http.ResponseWriter, r *http.Request, _, _ string) error {
	buckets, err := h.svc.ListBuckets(ctx)
	if err != nil {
		return err
	}
	res := listAllMyBucketsResult{Owner: owner, Buckets: []bucketXML{}}
	for _, b := range buckets {
		res.Buckets = append(res.Buckets, bucketXML{
			Name:             b.Name,
			CreationDate:     xmlTime(b.CreatedAt),
			Location:         "oss-" + h.region,
			ExtranetEndpoint: r.Host,
			IntranetEndpoint: r.Host,
			Region:           h.region,
			StorageClass:     storageClass,
		})
	}
	writeXML(w, http.StatusOK, res)
	return nil
}

func (h *Handler) putBucket(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, _ string) error {
	acl, err := parseACL(r.Header.Get("x-oss-acl"))
	if err != nil {
		return err
	}
	if err := h.svc.PutBucket(ctx, bucket, acl); err != nil {
		return err
	}
	w.Header().Set("Location", "/"+bucket)
	w.WriteHeader(http.StatusOK)
	return nil
}

func parseACL(value string) (storage.ACL, error) {
	switch value {
	case "", string(storage.ACLPrivate):
		return storage.ACLPrivate, nil
	case string(storage.ACLPublicRead):
		return storage.ACLPublicRead, nil
	}
	return "", invalidArgument("x-oss-acl must be private or public-read.")
}

func (h *Handler) deleteBucket(ctx context.Context, w http.ResponseWriter, _ *http.Request, bucket, _ string) error {
	if err := h.svc.DeleteBucket(ctx, bucket); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *Handler) getBucketInfo(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, _ string) error {
	b, err := h.svc.GetBucket(ctx, bucket)
	if err != nil {
		return err
	}
	writeXML(w, http.StatusOK, bucketInfoResult{Bucket: bucketInfoXML{
		Name:             b.Name,
		CreationDate:     xmlTime(b.CreatedAt),
		Location:         "oss-" + h.region,
		ExtranetEndpoint: r.Host,
		IntranetEndpoint: r.Host,
		Region:           h.region,
		StorageClass:     storageClass,
		Owner:            owner,
		Grant:            string(b.ACL),
	}})
	return nil
}

func (h *Handler) listObjects(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, _ string) error {
	q := r.URL.Query()
	enc, err := encoderOf(q.Get("encoding-type"))
	if err != nil {
		return err
	}
	res, err := h.svc.List(ctx, bucket, service.ListQuery{
		Prefix: q.Get("prefix"), Delimiter: q.Get("delimiter"), StartFrom: q.Get("marker"), MaxKeys: q.Get("max-keys"),
	})
	if err != nil {
		return err
	}
	out := listBucketResultV1{
		Name:           bucket,
		Prefix:         enc(q.Get("prefix")),
		Marker:         enc(q.Get("marker")),
		MaxKeys:        maxKeysOf(q.Get("max-keys")),
		Delimiter:      enc(q.Get("delimiter")),
		EncodingType:   q.Get("encoding-type"),
		IsTruncated:    res.IsTruncated,
		Contents:       contentsOf(res.Objects, enc, true),
		CommonPrefixes: prefixesOf(res.CommonPrefixes, enc),
	}
	if res.IsTruncated {
		out.NextMarker = enc(res.NextMarker)
	}
	writeXML(w, http.StatusOK, out)
	return nil
}

func (h *Handler) listObjectsV2(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, _ string) error {
	q := r.URL.Query()
	enc, err := encoderOf(q.Get("encoding-type"))
	if err != nil {
		return err
	}
	res, err := h.svc.List(ctx, bucket, service.ListQuery{
		Prefix: q.Get("prefix"), Delimiter: q.Get("delimiter"), StartFrom: q.Get("start-after"),
		Token: q.Get("continuation-token"), MaxKeys: q.Get("max-keys"),
	})
	if err != nil {
		return err
	}
	out := listBucketResultV2{
		Name:              bucket,
		Prefix:            enc(q.Get("prefix")),
		StartAfter:        enc(q.Get("start-after")),
		ContinuationToken: q.Get("continuation-token"),
		MaxKeys:           maxKeysOf(q.Get("max-keys")),
		Delimiter:         enc(q.Get("delimiter")),
		EncodingType:      q.Get("encoding-type"),
		IsTruncated:       res.IsTruncated,
		KeyCount:          len(res.Objects) + len(res.CommonPrefixes),
		Contents:          contentsOf(res.Objects, enc, q.Get("fetch-owner") == "true"),
		CommonPrefixes:    prefixesOf(res.CommonPrefixes, enc),
	}
	if res.IsTruncated {
		out.NextContinuationToken = res.NextToken
	}
	writeXML(w, http.StatusOK, out)
	return nil
}

// encoderOf returns how names are written in a listing: as they are, or URL encoded when the
// request asked for encoding-type=url.
func encoderOf(encodingType string) (func(string) string, error) {
	switch encodingType {
	case "":
		return func(s string) string { return s }, nil
	case "url":
		return url.QueryEscape, nil
	}
	return nil, invalidArgument("encoding-type must be url.")
}

// maxKeysOf reads a max-keys value the service has already validated.
func maxKeysOf(raw string) int {
	if n, err := strconv.Atoi(raw); err == nil {
		return n
	}
	return 100
}

func contentsOf(objects []storage.Object, enc func(string) string, withOwner bool) []contentXML {
	contents := make([]contentXML, 0, len(objects))
	for _, obj := range objects {
		c := contentXML{
			Key:          enc(obj.Key),
			LastModified: xmlTime(obj.LastModified),
			ETag:         etag(obj),
			Type:         objectType,
			Size:         obj.Size,
			StorageClass: storageClass,
		}
		if withOwner {
			c.Owner = &owner
		}
		contents = append(contents, c)
	}
	return contents
}

func prefixesOf(prefixes []string, enc func(string) string) []commonPrefixXML {
	out := make([]commonPrefixXML, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, commonPrefixXML{Prefix: enc(p)})
	}
	return out
}

func (h *Handler) deleteMultipleObjects(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, _ string) error {
	enc, err := encoderOf(r.URL.Query().Get("encoding-type"))
	if err != nil {
		return err
	}
	want := r.Header.Get("Content-MD5")
	if want == "" {
		return errBadDigest
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDeleteBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxDeleteBody {
		return invalidArgument("The request body is too large.")
	}
	sum := md5.Sum(body)
	if base64.StdEncoding.EncodeToString(sum[:]) != want {
		return errBadDigest
	}
	var req deleteRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		return newError(http.StatusBadRequest, "MalformedXML", "The XML you provided was not well-formed.")
	}
	if len(req.Objects) == 0 || len(req.Objects) > maxDeleteObjects {
		return invalidArgument("The number of objects must be between 1 and 1000.")
	}
	keys := make([]string, len(req.Objects))
	for i, o := range req.Objects {
		keys[i] = o.Key
	}
	deleted, err := h.svc.DeleteMany(ctx, bucket, keys)
	if err != nil {
		return err
	}
	res := deleteResult{EncodingType: r.URL.Query().Get("encoding-type")}
	if !req.Quiet {
		for _, key := range deleted {
			res.Deleted = append(res.Deleted, deletedXML{Key: enc(key)})
		}
	}
	writeXML(w, http.StatusOK, res)
	return nil
}

func (h *Handler) putObject(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, key string) error {
	var body io.Reader = r.Body
	if value := r.Header.Get("Content-MD5"); value != "" {
		want, err := base64.StdEncoding.DecodeString(value)
		if err != nil || len(want) != md5.Size {
			return errBadDigest
		}
		body = &digestReader{r: r.Body, hash: md5.New(), want: want}
	}
	obj, err := h.svc.Put(ctx, bucket, key, body, metaFromRequest(r), !forbidOverwrite(r))
	if err != nil {
		return err
	}
	w.Header().Set("ETag", etag(obj))
	w.WriteHeader(http.StatusOK)
	return nil
}

func (h *Handler) copyObject(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, key string) error {
	source, _, _ := strings.Cut(r.Header.Get("x-oss-copy-source"), "?")
	source, err := url.PathUnescape(source)
	if err != nil {
		return invalidArgument("x-oss-copy-source is invalid.")
	}
	srcBucket, srcKey, ok := strings.Cut(strings.TrimPrefix(source, "/"), "/")
	if !ok {
		return invalidArgument("x-oss-copy-source is invalid.")
	}
	if err := service.ValidateBucketName(srcBucket); err != nil {
		return err
	}
	if _, err := h.svc.GetBucket(ctx, srcBucket); err != nil {
		return err
	}
	var meta *storage.ObjectMeta
	switch r.Header.Get("x-oss-metadata-directive") {
	case "", "COPY":
	case "REPLACE":
		m := metaFromRequest(r)
		meta = &m
	default:
		return invalidArgument("x-oss-metadata-directive must be COPY or REPLACE.")
	}
	obj, err := h.svc.Copy(ctx, srcBucket, srcKey, bucket, key, meta, !forbidOverwrite(r))
	if err != nil {
		return err
	}
	w.Header().Set("ETag", etag(obj))
	writeXML(w, http.StatusOK, copyObjectResult{LastModified: xmlTime(obj.LastModified), ETag: etag(obj)})
	return nil
}

func (h *Handler) getObject(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket, key string) error {
	header, standard := r.Header.Get("Range"), isStandardRange(r)
	rc, obj, rng, err := h.svc.Get(ctx, bucket, key, func(size int64) (*storage.ByteRange, error) {
		return parseRange(header, size, standard)
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := rc.Close(); err != nil {
			slog.Warn("close object failed", "bucket", bucket, "key", key, "err", err)
		}
	}()

	writeObjectHeaders(w, obj)
	q := r.URL.Query()
	for param, name := range responseOverrides {
		if q.Has(param) {
			w.Header().Set(name, q.Get(param))
		}
	}
	status := http.StatusOK
	if rng != nil {
		status = http.StatusPartialContent
		w.Header().Set("Content-Range", "bytes "+strconv.FormatInt(rng.Start, 10)+"-"+strconv.FormatInt(rng.End, 10)+"/"+strconv.FormatInt(obj.Size, 10))
		w.Header().Set("Content-Length", strconv.FormatInt(rng.End-rng.Start+1, 10))
	}
	w.WriteHeader(status)
	if _, err := io.Copy(w, rc); err != nil {
		slog.Debug("stream object failed", "bucket", bucket, "key", key, "err", err)
	}
	return nil
}

func (h *Handler) headObject(ctx context.Context, w http.ResponseWriter, _ *http.Request, bucket, key string) error {
	obj, err := h.svc.Head(ctx, bucket, key)
	if err != nil {
		return err
	}
	writeObjectHeaders(w, obj)
	w.WriteHeader(http.StatusOK)
	return nil
}

func (h *Handler) getObjectMeta(ctx context.Context, w http.ResponseWriter, _ *http.Request, bucket, key string) error {
	obj, err := h.svc.Head(ctx, bucket, key)
	if err != nil {
		return err
	}
	hd := w.Header()
	hd.Set("Content-Length", strconv.FormatInt(obj.Size, 10))
	hd.Set("ETag", etag(obj))
	hd.Set("Last-Modified", obj.LastModified.UTC().Format(http.TimeFormat))
	w.WriteHeader(http.StatusOK)
	return nil
}

func (h *Handler) deleteObject(ctx context.Context, w http.ResponseWriter, _ *http.Request, bucket, key string) error {
	if err := h.svc.Delete(ctx, bucket, key); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func writeObjectHeaders(w http.ResponseWriter, obj storage.Object) {
	hd := w.Header()
	hd.Set("Content-Type", obj.ContentType)
	hd.Set("Content-Length", strconv.FormatInt(obj.Size, 10))
	hd.Set("ETag", etag(obj))
	hd.Set("Last-Modified", obj.LastModified.UTC().Format(http.TimeFormat))
	hd.Set("Accept-Ranges", "bytes")
	hd.Set("x-oss-object-type", objectType)
	hd.Set("x-oss-storage-class", storageClass)
	for name, value := range obj.UserMeta {
		hd.Set(userMetaPrefix+name, value)
	}
}

// metaFromRequest reads Content-Type and x-oss-meta-* from a write request. A missing
// Content-Type is stored as application/octet-stream, as OSS does.
func metaFromRequest(r *http.Request) storage.ObjectMeta {
	meta := storage.ObjectMeta{ContentType: r.Header.Get("Content-Type")}
	if meta.ContentType == "" {
		meta.ContentType = "application/octet-stream"
	}
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, userMetaPrefix) {
			if meta.UserMeta == nil {
				meta.UserMeta = make(map[string]string)
			}
			meta.UserMeta[strings.TrimPrefix(lower, userMetaPrefix)] = joinHeaderValues(values)
		}
	}
	return meta
}

func forbidOverwrite(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("x-oss-forbid-overwrite"), "true")
}

// digestReader fails the body at EOF when its MD5 differs from Content-MD5. Failing inside the
// read makes the store abort the write before it commits anything.
type digestReader struct {
	r    io.Reader
	hash hash.Hash // Write never returns an error
	want []byte
}

func (d *digestReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	d.hash.Write(p[:n])
	if err == io.EOF && !bytes.Equal(d.hash.Sum(nil), d.want) {
		return n, errBadDigest
	}
	return n, err
}
