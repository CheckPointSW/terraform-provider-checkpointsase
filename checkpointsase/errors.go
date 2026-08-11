package checkpointsase

import (
	"net/http"
	"strings"
)

// apiErrorKind classifies an SDK error so callers can apply the provider's
// drift and idempotency conventions consistently.
//
// Before this existed every error went through appendErrorDiags uniformly,
// which is why deletes were not idempotent and why a vanished parent network
// surfaced as a hard failure instead of drift.
type apiErrorKind int

const (
	// errKindOther is a genuine failure the caller should surface.
	errKindOther apiErrorKind = iota
	// errKindNotFound means the object is gone: drift on Read, success on Delete.
	errKindNotFound
	// errKindConflict means the server rejected the request due to state.
	errKindConflict
	// errKindTransient is worth retrying: 5xx, EOF, connection reset.
	errKindTransient
)

// transientErrorFragments are substrings of errors that are worth retrying when
// no HTTP response is available to classify.
var transientErrorFragments = []string{
	"unexpected eof",
	"connection reset",
	"connection refused",
	"broken pipe",
	"timeout",
	"temporary failure",
}

// classifyAPIError buckets an SDK error. resp may be nil when the request never
// reached the server. err must be non-nil for any kind other than errKindOther.
func classifyAPIError(resp *http.Response, err error) apiErrorKind {
	if err == nil {
		return errKindOther
	}
	if resp != nil {
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return errKindNotFound
		case resp.StatusCode == http.StatusConflict:
			return errKindConflict
		case resp.StatusCode >= 500:
			return errKindTransient
		default:
			return errKindOther
		}
	}
	msg := strings.ToLower(err.Error())
	for _, fragment := range transientErrorFragments {
		if strings.Contains(msg, fragment) {
			return errKindTransient
		}
	}
	return errKindOther
}

// isNotFound reports whether the object the request targeted is absent.
func isNotFound(resp *http.Response, err error) bool {
	return classifyAPIError(resp, err) == errKindNotFound
}
