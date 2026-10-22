package s3

import (
	"net/http"
	"strings"

	"github.com/dofunc/oss-go-fake/internal/protocol"
)

// Reserved recognises S3 requests so they get a clear 501 instead of an OSS signature error.
type Reserved struct{}

var _ protocol.Protocol = Reserved{}

func (Reserved) Name() string { return "S3" }

func (Reserved) Claims(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	q := r.URL.Query()
	return strings.HasPrefix(auth, "AWS ") || strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") ||
		q.Has("X-Amz-Algorithm") || q.Has("AWSAccessKeyId")
}

func (p Reserved) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	protocol.NotEnabled(w, r, p.Name())
}
