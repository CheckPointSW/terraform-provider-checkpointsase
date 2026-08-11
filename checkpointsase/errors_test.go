package checkpointsase

import (
	"errors"
	"io"
	"net/http"
	"testing"
)

func resp(code int) *http.Response { return &http.Response{StatusCode: code} }

func TestClassifyAPIError(t *testing.T) {
	tests := []struct {
		name string
		resp *http.Response
		err  error
		want apiErrorKind
	}{
		{"404 is not found", resp(http.StatusNotFound), errors.New("not found"), errKindNotFound},
		{"409 is conflict", resp(http.StatusConflict), errors.New("conflict"), errKindConflict},
		{"500 is transient", resp(http.StatusInternalServerError), errors.New("boom"), errKindTransient},
		{"503 is transient", resp(http.StatusServiceUnavailable), errors.New("boom"), errKindTransient},
		{"400 is other", resp(http.StatusBadRequest), errors.New("bad"), errKindOther},
		{"403 is other", resp(http.StatusForbidden), errors.New("forbidden"), errKindOther},
		{"unexpected EOF with no response is transient", nil, io.ErrUnexpectedEOF, errKindTransient},
		{"connection reset with no response is transient", nil, errors.New("read: connection reset by peer"), errKindTransient},
		{"unknown error with no response is other", nil, errors.New("kaboom"), errKindOther},
		{"nil error is other", nil, nil, errKindOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyAPIError(tc.resp, tc.err); got != tc.want {
				t.Errorf("classifyAPIError() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsNotFound(t *testing.T) {
	if !isNotFound(resp(404), errors.New("nope")) {
		t.Error("404 should report not found")
	}
	if isNotFound(resp(500), errors.New("nope")) {
		t.Error("500 should not report not found")
	}
}
