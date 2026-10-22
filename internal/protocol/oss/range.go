package oss

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/dofunc/oss-go-fake/internal/service"
	"github.com/dofunc/oss-go-fake/internal/storage"
)

// parseRange turns a Range header into the byte range to serve, nil meaning the whole object.
//
// By default OSS ignores a range it cannot satisfy and returns the whole object with 200. With
// x-oss-range-behavior: standard, an end past the object is clamped and a start past it fails
// with 416. Malformed and multi-range headers are ignored in both modes.
func parseRange(header string, size int64, standard bool) (*storage.ByteRange, error) {
	spec, ok := strings.CutPrefix(header, "bytes=")
	if !ok || strings.Contains(spec, ",") {
		return nil, nil
	}
	first, last, ok := strings.Cut(strings.TrimSpace(spec), "-")
	if !ok {
		return nil, nil
	}

	if first == "" { // suffix range: the last n bytes
		n, err := strconv.ParseInt(last, 10, 64)
		if err != nil || n <= 0 {
			return nil, nil
		}
		if n > size {
			if !standard {
				return nil, nil
			}
			n = size
		}
		if n == 0 {
			return nil, unsatisfiable()
		}
		return &storage.ByteRange{Start: size - n, End: size - 1}, nil
	}

	start, err := strconv.ParseInt(first, 10, 64)
	if err != nil || start < 0 {
		return nil, nil
	}
	end := size - 1
	if last != "" {
		if end, err = strconv.ParseInt(last, 10, 64); err != nil || end < start {
			return nil, nil
		}
	}
	if start >= size {
		if !standard {
			return nil, nil
		}
		return nil, unsatisfiable()
	}
	if end >= size {
		if !standard && last != "" {
			return nil, nil
		}
		end = size - 1
	}
	return &storage.ByteRange{Start: start, End: end}, nil
}

func unsatisfiable() error {
	return &service.Error{Kind: service.KindInvalidRange, Message: "The requested range cannot be satisfied."}
}

func isStandardRange(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("x-oss-range-behavior"), "standard")
}
