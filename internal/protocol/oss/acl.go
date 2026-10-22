package oss

import (
	"net/http"

	"github.com/dofunc/oss-go-fake/internal/service"
	"github.com/dofunc/oss-go-fake/internal/storage"
)

var errAnonymousForbidden = newError(http.StatusForbidden, "AccessDenied", "Anonymous access is forbidden for this operation.")

// authorize applies the bucket ACL to a routed request. Routes without a bucket record behind
// them (ListBuckets, PutBucket) are never open to anonymous callers.
func authorize(rt route, b storage.Bucket, authenticated bool) error {
	if rt.bucketless {
		if !authenticated {
			return errAnonymousForbidden
		}
		return nil
	}
	if !service.Allowed(b, rt.op, authenticated) {
		return errAnonymous
	}
	return nil
}
