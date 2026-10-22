package oss

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	v4Algorithm     = "OSS4-HMAC-SHA256"
	v4DateFormat    = "20060102T150405Z"
	v4Terminator    = "aliyun_v4_request"
	unsignedPayload = "UNSIGNED-PAYLOAD"
)

// canonicalRequestV4 builds the canonical request. presigned drops x-oss-signature from the
// query and never reads x-oss-content-sha256, which a URL cannot carry.
func canonicalRequestV4(r *http.Request, bucket, key string, additional []string, presigned bool) string {
	var uri string
	switch {
	case bucket == "":
		uri = "/"
	case key == "":
		uri = "/" + bucket + "/"
	default:
		uri = "/" + bucket + "/" + key
	}

	query := r.URL.Query()
	if presigned {
		query.Del("x-oss-signature")
	}
	type param struct{ name, value string }
	params := make([]param, 0, len(query))
	for name, values := range query {
		params = append(params, param{uriEncode(strings.TrimSpace(name), true), uriEncode(strings.TrimSpace(values[0]), true)})
	}
	// Sort by encoded name, never by the joined "name=value": "a-x=1" sorts before "a=1" as a
	// string, while the SDK's TreeMap keyed by name puts "a" first.
	sort.Slice(params, func(i, j int) bool { return params[i].name < params[j].name })
	pairs := make([]string, 0, len(params))
	for _, p := range params {
		if p.value == "" {
			pairs = append(pairs, p.name) // an empty value signs as the bare name, no '='
		} else {
			pairs = append(pairs, p.name+"="+p.value)
		}
	}

	signed := map[string]bool{"content-type": true, "content-md5": true}
	for _, h := range additional {
		signed[h] = true
	}
	var headers []string
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if signed[lower] || strings.HasPrefix(lower, "x-oss-") {
			headers = append(headers, lower+":"+joinHeaderValues(values)+"\n")
		}
	}
	if slices.Contains(additional, "host") {
		headers = append(headers, "host:"+r.Host+"\n")
	}
	sort.Strings(headers)

	return strings.Join([]string{
		r.Method,
		uriEncode(uri, false),
		strings.Join(pairs, "&"),
		strings.Join(headers, ""),
		strings.Join(additional, ";"),
		unsignedPayload,
	}, "\n")
}

// verifyV4 checks a V4 signature, from the Authorization header or from the x-oss-* query
// parameters of a signed URL, and returns the access key id.
func (a *Authenticator) verifyV4(r *http.Request, bucket, key string, now time.Time) (string, error) {
	q := r.URL.Query()
	presigned := q.Has("x-oss-signature-version")
	var credential, additional, signature, datetime string
	if presigned {
		if q.Get("x-oss-signature-version") != v4Algorithm {
			return "", invalidArgument("x-oss-signature-version is invalid.")
		}
		credential, additional, signature = q.Get("x-oss-credential"), q.Get("x-oss-additional-headers"), q.Get("x-oss-signature")
		datetime = q.Get("x-oss-date")
	} else {
		fields := parseV4Authorization(strings.TrimPrefix(r.Header.Get("Authorization"), v4Algorithm+" "))
		credential, additional, signature = fields["Credential"], fields["AdditionalHeaders"], fields["Signature"]
		datetime = r.Header.Get("x-oss-date")
	}

	scope := strings.Split(credential, "/")
	if len(scope) != 5 || scope[3] != "oss" || scope[4] != v4Terminator {
		return "", newError(http.StatusForbidden, "SignatureDoesNotMatch", "The credential scope is invalid.")
	}
	accessKeyID, date, region := scope[0], scope[1], scope[2]
	secret, err := a.secret(accessKeyID)
	if err != nil {
		return "", err
	}
	if region != a.region {
		return "", newError(http.StatusForbidden, "SignatureDoesNotMatch", "Invalid signing region in credential scope.")
	}

	t, err := time.Parse(v4DateFormat, datetime)
	if presigned {
		expires, convErr := strconv.ParseInt(q.Get("x-oss-expires"), 10, 64)
		if err != nil || convErr != nil || expires < 1 || expires > maxPresignExpiry {
			return "", newError(http.StatusForbidden, "AccessDenied", "x-oss-date or x-oss-expires is invalid.")
		}
		if t.Add(time.Duration(expires) * time.Second).Before(now) {
			return "", newError(http.StatusForbidden, "AccessDenied", "Request has expired.")
		}
	} else {
		if err != nil {
			return "", newError(http.StatusForbidden, "AccessDenied", "x-oss-date is invalid.")
		}
		if err := checkSkew(t, now); err != nil {
			return "", err
		}
		if r.Header.Get("x-oss-content-sha256") != unsignedPayload {
			return "", invalidArgument("x-oss-content-sha256 must be UNSIGNED-PAYLOAD.")
		}
	}

	var headers []string
	if additional != "" {
		for _, h := range strings.Split(additional, ";") {
			headers = append(headers, strings.ToLower(strings.TrimSpace(h)))
		}
	}
	canonical := canonicalRequestV4(r, bucket, key, headers, presigned)
	stringToSign := stringToSignV4(datetime, date+"/"+region+"/oss/"+v4Terminator, canonical)
	expected := hex.EncodeToString(hmacSHA256(signingKeyV4(secret, date, region), stringToSign))
	return accessKeyID, compareSignature(accessKeyID, signature, expected, stringToSign, canonical)
}

// parseV4Authorization splits "Credential=..,AdditionalHeaders=..,Signature=.." into its fields,
// with or without spaces after the commas.
func parseV4Authorization(s string) map[string]string {
	fields := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		if name, value, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
			fields[name] = value
		}
	}
	return fields
}

func stringToSignV4(datetime, scope, canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return v4Algorithm + "\n" + datetime + "\n" + scope + "\n" + hex.EncodeToString(sum[:])
}

func signingKeyV4(secret, date, region string) []byte {
	k := hmacSHA256([]byte("aliyun_v4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, "oss")
	return hmacSHA256(k, v4Terminator)
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// uriEncode percent-encodes s per RFC 3986: only A-Z a-z 0-9 - _ . ~ stay as they are, and
// '/' too unless encodeSlash is set. Hex digits are upper case.
func uriEncode(s string, encodeSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) || (c == '/' && !encodeSlash) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}

func isUnreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
		c == '-' || c == '_' || c == '.' || c == '~'
}
