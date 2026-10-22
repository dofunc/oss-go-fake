package oss

import (
	"crypto/hmac"
	"net/http"
	"strings"
	"time"
)

const (
	maxClockSkew     = 15 * time.Minute
	maxPresignExpiry = 604800 // seconds, the V4 URL limit
)

// Authenticator verifies OSS V1 and V4 signatures, in the Authorization header or in the URL,
// against the configured access keys.
type Authenticator struct {
	secrets map[string]string // access key id -> secret
	region  string
	now     func() time.Time
}

func NewAuthenticator(secrets map[string]string, region string, now func() time.Time) *Authenticator {
	return &Authenticator{secrets: secrets, region: region, now: now}
}

// Verify reports whether the request carries a signature, and the error when a signature is
// there but does not hold. An unsigned request is anonymous and returns (false, nil).
func (a *Authenticator) Verify(r *http.Request, bucket, key string) (bool, error) {
	auth := r.Header.Get("Authorization")
	q := r.URL.Query()
	now := a.now()
	var err error
	switch {
	case strings.HasPrefix(auth, v4Algorithm+" "), q.Has("x-oss-signature-version"):
		_, err = a.verifyV4(r, bucket, key, now)
	case strings.HasPrefix(auth, "OSS "):
		_, err = a.verifyV1Header(r, bucket, key, now)
	case q.Has("OSSAccessKeyId"):
		_, err = a.verifyV1Query(r, bucket, key, now)
	case auth != "":
		err = invalidArgument("Authorization header is invalid.")
	default:
		return false, nil
	}
	return true, err
}

func (a *Authenticator) secret(accessKeyID string) (string, error) {
	secret, ok := a.secrets[accessKeyID]
	if !ok {
		return "", newError(http.StatusForbidden, "InvalidAccessKeyId", "The OSS Access Key Id you provided does not exist in our records.")
	}
	return secret, nil
}

func checkSkew(t, now time.Time) error {
	skew := now.Sub(t)
	if skew > maxClockSkew || skew < -maxClockSkew {
		return newError(http.StatusForbidden, "RequestTimeTooSkewed", "The difference between the request time and the current time is too large.")
	}
	return nil
}

func compareSignature(accessKeyID, provided, expected, stringToSign, canonical string) error {
	if hmac.Equal([]byte(provided), []byte(expected)) {
		return nil
	}
	return &ossError{
		status:           http.StatusForbidden,
		code:             "SignatureDoesNotMatch",
		message:          "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
		accessKeyID:      accessKeyID,
		stringToSign:     stringToSign,
		canonicalRequest: canonical,
	}
}
