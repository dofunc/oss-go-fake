package oss

import (
	"net"
	"net/http"
	"strings"
)

// parseAddress finds the bucket and key of a request. A Host ending in ".<domain>" is
// virtual-hosted and names the bucket; anything else is path-style, with the bucket as the
// first path segment. An empty domain accepts path-style only. The key is the decoded path,
// kept byte for byte: "a//b" and "../x" are ordinary object names.
func parseAddress(r *http.Request, domain string) (bucket, key string) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	path := strings.TrimPrefix(r.URL.Path, "/")
	if domain != "" && strings.HasSuffix(host, "."+domain) {
		return strings.TrimSuffix(host, "."+domain), path
	}
	bucket, key, _ = strings.Cut(path, "/")
	return bucket, key
}
