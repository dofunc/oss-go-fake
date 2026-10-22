package oss

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/dofunc/oss-go-fake/internal/config"
)

// preflight answers a CORS preflight. It needs no signature and ignores the bucket ACL: only
// the bucket's CORS rules decide. The real request that follows is authenticated as usual.
func (h *Handler) preflight(ctx context.Context, w http.ResponseWriter, r *http.Request, bucket string) error {
	method := r.Header.Get("Access-Control-Request-Method")
	origin := r.Header.Get("Origin")
	if bucket == "" || method == "" || origin == "" {
		return errCORSDenied
	}
	if _, err := h.svc.GetBucket(ctx, bucket); err != nil {
		return err
	}
	var requested []string
	for _, name := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			requested = append(requested, name)
		}
	}
	rule := matchRule(h.cors[bucket], origin, method, requested)
	if rule == nil {
		return errCORSDenied
	}
	writeCORSHeaders(w, rule, origin)
	if len(requested) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(requested, ", "))
	}
	if rule.MaxAgeSeconds > 0 {
		w.Header().Set("Access-Control-Max-Age", strconv.Itoa(rule.MaxAgeSeconds))
	}
	w.WriteHeader(http.StatusOK)
	return nil
}

var errCORSDenied = newError(http.StatusForbidden, "AccessForbidden",
	"CORSResponse: This CORS request is not allowed. This is usually because the evalution of Origin, request method / Access-Control-Request-Method or Access-Control-Requet-Headers are not whitelisted by the resource's CORS spec.")

// applyCORS adds the CORS response headers to a real (non-preflight) request whose Origin and
// method match a rule of the bucket.
func applyCORS(w http.ResponseWriter, r *http.Request, rules []config.CORSRule) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	if rule := matchRule(rules, origin, r.Method, nil); rule != nil {
		writeCORSHeaders(w, rule, origin)
	}
}

func writeCORSHeaders(w http.ResponseWriter, rule *config.CORSRule, origin string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Methods", strings.Join(rule.AllowedMethods, ", "))
	if len(rule.ExposeHeaders) > 0 {
		h.Set("Access-Control-Expose-Headers", strings.Join(rule.ExposeHeaders, ", "))
	}
	h.Add("Vary", "Origin")
}

// matchRule returns the first rule allowing origin, method and every requested header.
func matchRule(rules []config.CORSRule, origin, method string, headers []string) *config.CORSRule {
	for i := range rules {
		rule := &rules[i]
		if anyMatch(rule.AllowedOrigins, origin, false) && anyMatch(rule.AllowedMethods, method, false) &&
			allMatch(rule.AllowedHeaders, headers) {
			return rule
		}
	}
	return nil
}

func allMatch(patterns, values []string) bool {
	for _, v := range values {
		if !anyMatch(patterns, v, true) {
			return false
		}
	}
	return true
}

func anyMatch(patterns []string, value string, foldCase bool) bool {
	for _, p := range patterns {
		if foldCase {
			p, value = strings.ToLower(p), strings.ToLower(value)
		}
		if wildcardMatch(p, value) {
			return true
		}
	}
	return false
}

// wildcardMatch matches value against a pattern holding at most one '*', as OSS CORS rules do.
func wildcardMatch(pattern, value string) bool {
	before, after, found := strings.Cut(pattern, "*")
	if !found {
		return pattern == value
	}
	return len(value) >= len(before)+len(after) && strings.HasPrefix(value, before) && strings.HasSuffix(value, after)
}
