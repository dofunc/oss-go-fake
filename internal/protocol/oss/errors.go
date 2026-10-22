package oss

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"log/slog"
	"net/http"

	"github.com/dofunc/oss-go-fake/internal/service"
)

// ecUnmapped is the EC every error carries: real OSS has a fine-grained EC per failure that
// the fake does not reproduce.
const ecUnmapped = "0000-00000000"

// ossError is a protocol-level failure with its OSS status and code. Signature failures also
// carry what the server signed, as real OSS reports it, so a client can diff its own side.
type ossError struct {
	status           int
	code             string
	message          string
	accessKeyID      string
	stringToSign     string
	canonicalRequest string
}

func (e *ossError) Error() string { return e.code + ": " + e.message }

func newError(status int, code, message string) *ossError {
	return &ossError{status: status, code: code, message: message}
}

var (
	errBadDigest = newError(http.StatusBadRequest, "InvalidDigest", "The Content-MD5 you specified is not valid.")
	errAnonymous = newError(http.StatusForbidden, "AccessDenied", "You have no right to access this object because of bucket acl.")
)

func notImplemented(what string) *ossError {
	return newError(http.StatusNotImplemented, "NotImplemented", what+" is not implemented.")
}

func invalidArgument(message string) *ossError {
	return newError(http.StatusBadRequest, "InvalidArgument", message)
}

var kindStatus = map[service.Kind]struct {
	status int
	code   string
}{
	service.KindInvalidBucketName:   {http.StatusBadRequest, "InvalidBucketName"},
	service.KindInvalidObjectName:   {http.StatusBadRequest, "InvalidObjectName"},
	service.KindInvalidArgument:     {http.StatusBadRequest, "InvalidArgument"},
	service.KindNoSuchBucket:        {http.StatusNotFound, "NoSuchBucket"},
	service.KindNoSuchKey:           {http.StatusNotFound, "NoSuchKey"},
	service.KindBucketAlreadyExists: {http.StatusConflict, "BucketAlreadyExists"},
	service.KindBucketNotEmpty:      {http.StatusConflict, "BucketNotEmpty"},
	service.KindObjectAlreadyExists: {http.StatusConflict, "FileAlreadyExists"},
	service.KindAccessDenied:        {http.StatusForbidden, "AccessDenied"},
	service.KindInvalidRange:        {http.StatusRequestedRangeNotSatisfiable, "InvalidRange"},
}

// toOSSError maps any error to the OSS error a client sees. Errors nobody classified are
// server faults: they are logged and answered with 500 InternalError.
func toOSSError(r *http.Request, err error) *ossError {
	var oe *ossError
	if errors.As(err, &oe) {
		return oe
	}
	var se *service.Error
	if errors.As(err, &se) {
		if m, ok := kindStatus[se.Kind]; ok {
			return newError(m.status, m.code, se.Message)
		}
	}
	slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	return newError(http.StatusInternalServerError, "InternalError", "We encountered an internal error. Please try again.")
}

type errorXML struct {
	XMLName          xml.Name `xml:"Error"`
	Code             string   `xml:"Code"`
	Message          string   `xml:"Message"`
	RequestID        string   `xml:"RequestId"`
	HostID           string   `xml:"HostId"`
	OSSAccessKeyID   string   `xml:"OSSAccessKeyId,omitempty"`
	StringToSign     string   `xml:"StringToSign,omitempty"`
	CanonicalRequest string   `xml:"CanonicalRequest,omitempty"`
	EC               string   `xml:"EC"`
}

// writeError answers with the OSS error XML. Every error response also carries the same XML,
// base64 encoded, in x-oss-err: a HEAD response has no body, and that header is where SDKs
// look for the real error code.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	oe := toOSSError(r, err)
	body, encErr := xml.Marshal(errorXML{
		Code:             oe.code,
		Message:          oe.message,
		RequestID:        w.Header().Get(headerRequestID),
		HostID:           r.Host,
		OSSAccessKeyID:   oe.accessKeyID,
		StringToSign:     oe.stringToSign,
		CanonicalRequest: oe.canonicalRequest,
		EC:               ecUnmapped,
	})
	if encErr != nil {
		slog.Error("encode error response failed", "err", encErr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	body = append([]byte(xml.Header), body...)
	h := w.Header()
	h.Set("Content-Type", "application/xml")
	h.Set("x-oss-ec", ecUnmapped)
	h.Set("x-oss-err", base64.StdEncoding.EncodeToString(body))
	h.Del("Content-Length")
	h.Del("ETag")
	w.WriteHeader(oe.status)
	if r.Method != http.MethodHead {
		writeBody(w, body)
	}
}

func writeBody(w http.ResponseWriter, body []byte) {
	if _, err := w.Write(body); err != nil {
		slog.Debug("write response failed", "err", err)
	}
}
