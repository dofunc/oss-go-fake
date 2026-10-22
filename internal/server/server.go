// Package server runs the HTTP listener and hands each request to the protocol it speaks.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/dofunc/oss-go-fake/internal/protocol"
)

const readHeaderTimeout = 30 * time.Second

// Server wraps http.Server with request ids, access logs and protocol detection. Request bodies
// have no size limit: objects stream straight to storage.
type Server struct {
	srv *http.Server
	ln  net.Listener
}

// Listen binds addr. Serve starts answering; the address is bound before it returns, so the
// caller can report readiness as soon as Listen succeeds.
func Listen(addr string, enabled, reserved []protocol.Protocol) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Server{
		srv: &http.Server{Handler: Handler(enabled, reserved), ReadHeaderTimeout: readHeaderTimeout},
		ln:  ln,
	}, nil
}

func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Serve blocks until Shutdown and returns nil then, or the error that stopped serving.
func (s *Server) Serve() error {
	if err := s.srv.Serve(s.ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops accepting and waits for in-flight requests until ctx expires.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// Handler is the middleware chain: request id, access log, protocol detection. enabled must
// not be empty.
func Handler(enabled, reserved []protocol.Protocol) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := requestID()
		w.Header().Set("x-oss-request-id", id)
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()

		if p, ok := protocol.Detect(r, enabled, reserved); ok {
			p.ServeHTTP(rec, r)
		} else {
			protocol.NotEnabled(rec, r, p.Name())
		}

		slog.Info("request",
			"id", id, "method", r.Method, "host", r.Host, "uri", r.RequestURI,
			"status", rec.status, "bytes", rec.bytes, "duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr)
	})
}

func requestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *recorder) Write(p []byte) (int, error) {
	n, err := r.ResponseWriter.Write(p)
	r.bytes += int64(n)
	return n, err
}
