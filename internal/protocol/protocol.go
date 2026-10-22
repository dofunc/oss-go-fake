// Package protocol decides which wire protocol a request speaks.
package protocol

import (
	"encoding/xml"
	"log/slog"
	"net/http"
)

type Protocol interface {
	Name() string
	// Claims reports whether the request carries this protocol's signature markers.
	Claims(r *http.Request) bool
	http.Handler
}

// Detect picks the protocol whose markers the request carries. An unsigned request goes to
// the first enabled protocol: anonymous reads look the same in every protocol.
func Detect(r *http.Request, enabled []Protocol, reserved []Protocol) (Protocol, bool) {
	for _, p := range enabled {
		if p.Claims(r) {
			return p, true
		}
	}
	for _, p := range reserved {
		if p.Claims(r) {
			return p, false // recognised but not enabled: caller answers 501
		}
	}
	return enabled[0], true
}

type notEnabledError struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
}

// NotEnabled answers a request whose protocol is recognised but not enabled in this release.
func NotEnabled(w http.ResponseWriter, r *http.Request, name string) {
	body, err := xml.Marshal(notEnabledError{
		Code:      "NotImplemented",
		Message:   name + " protocol is not enabled",
		RequestID: w.Header().Get("x-oss-request-id"),
	})
	if err != nil {
		slog.Error("encode error response failed", "err", err)
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotImplemented)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := w.Write(append([]byte(xml.Header), body...)); err != nil {
		slog.Debug("write response failed", "err", err)
	}
}
