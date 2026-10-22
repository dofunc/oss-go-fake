package oss

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// v1SubResources are the query parameters that enter the V1 canonicalized resource. It is the
// union of what aliyun-sdk-oss for Java (SignUtils) and alibabacloud-oss-go-sdk-v2 (signer/v1.go)
// sign, since the server must accept both. The Go SDK also signs every x-oss-* parameter,
// handled in stringToSignV1.
var v1SubResources = map[string]bool{
	"acl": true, "uploads": true, "location": true, "cors": true, "logging": true,
	"website": true, "referer": true, "lifecycle": true, "delete": true, "append": true,
	"tagging": true, "uploadId": true, "partNumber": true, "security-token": true,
	"position": true, "response-content-type": true, "response-content-language": true,
	"response-expires": true, "response-cache-control": true,
	"response-content-disposition": true, "response-content-encoding": true,
	"objectMeta": true, "bucketInfo": true, "continuation-token": true, "stat": true,
	"restore": true, "callback": true, "callback-var": true, "versions": true,
	"versioning": true, "versionId": true, "sequential": true, "regionList": true,
	"cloudboxes": true, "symlink": true,
}

func stringToSignV1(r *http.Request, bucket, key, dateOrExpires string) string {
	var ossHeaders []string
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-oss-") {
			ossHeaders = append(ossHeaders, lower+":"+joinHeaderValues(values))
		}
	}
	sort.Strings(ossHeaders)
	canonicalHeaders := ""
	for _, h := range ossHeaders {
		canonicalHeaders += h + "\n"
	}

	resource := "/"
	if bucket != "" {
		resource = "/" + bucket + "/" + key
	}
	query := r.URL.Query()
	var names []string
	for name := range query {
		if v1SubResources[name] || strings.HasPrefix(name, "x-oss-") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	subs := make([]string, 0, len(names))
	for _, name := range names {
		if value := query.Get(name); value == "" {
			subs = append(subs, name)
		} else {
			subs = append(subs, name+"="+value)
		}
	}
	if len(subs) > 0 {
		resource += "?" + strings.Join(subs, "&")
	}

	return r.Method + "\n" + r.Header.Get("Content-MD5") + "\n" + r.Header.Get("Content-Type") + "\n" +
		dateOrExpires + "\n" + canonicalHeaders + resource
}

// verifyV1Header checks "Authorization: OSS <ak>:<signature>" and returns the access key id.
func (a *Authenticator) verifyV1Header(r *http.Request, bucket, key string, now time.Time) (string, error) {
	accessKeyID, signature, ok := strings.Cut(strings.TrimPrefix(r.Header.Get("Authorization"), "OSS "), ":")
	if !ok {
		return "", invalidArgument("Authorization header is invalid.")
	}
	secret, err := a.secret(accessKeyID)
	if err != nil {
		return "", err
	}
	date := r.Header.Get("Date")
	t, err := http.ParseTime(date)
	if err != nil {
		return "", newError(http.StatusForbidden, "AccessDenied", "OSS authentication requires a valid Date.")
	}
	if err := checkSkew(t, now); err != nil {
		return "", err
	}
	stringToSign := stringToSignV1(r, bucket, key, date)
	return accessKeyID, compareSignature(accessKeyID, signature, signV1(secret, stringToSign), stringToSign, "")
}

// verifyV1Query checks a V1 signed URL and returns the access key id. A repeated parameter
// counts with its first value, and expiry is checked before the signature.
func (a *Authenticator) verifyV1Query(r *http.Request, bucket, key string, now time.Time) (string, error) {
	q := r.URL.Query()
	accessKeyID := q.Get("OSSAccessKeyId")
	secret, err := a.secret(accessKeyID)
	if err != nil {
		return "", err
	}
	expires := q.Get("Expires")
	at, err := strconv.ParseInt(expires, 10, 64)
	if err != nil {
		return "", newError(http.StatusForbidden, "AccessDenied", "Expires is invalid.")
	}
	if now.Unix() > at {
		return "", newError(http.StatusForbidden, "AccessDenied", "Request has expired.")
	}
	stringToSign := stringToSignV1(r, bucket, key, expires)
	return accessKeyID, compareSignature(accessKeyID, q.Get("Signature"), signV1(secret, stringToSign), stringToSign, "")
}

func signV1(secret, stringToSign string) string {
	h := hmac.New(sha1.New, []byte(secret))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// joinHeaderValues joins every value of a repeated header, each trimmed, with ",".
func joinHeaderValues(values []string) string {
	trimmed := make([]string, len(values))
	for i, v := range values {
		trimmed[i] = strings.TrimSpace(v)
	}
	return strings.Join(trimmed, ",")
}
