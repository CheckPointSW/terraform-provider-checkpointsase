package checkpointsase

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

/*
TestAppendErrorDiagsRecoversTheBodyThroughAWrappedError pins the half of
appendErrorDiags that a bare type assertion was silently losing.
The SDK's GenericOpenAPIError carries the server's message body -- `"fromDefault"
is not allowed`, `VALIDATION_WEB_RULES_REQUIRED` -- while its Error() carries
only `422 Unprocessable Entity`. appendErrorDiags used `err.(*GenericOpenAPIError)`,
which is false the moment anything wraps the error with %w, and something already
does: async.go's withStatusID. On that path the operator was being shown the
status line and nothing else.
The unwrapped row is the regression guard for the 283 existing call sites; the
wrapped rows are the defect. errors.As is also what isMembershipAlreadyAbsent
already uses, so this makes the two agree.
*/
func TestAppendErrorDiagsRecoversTheBodyThroughAWrappedError(t *testing.T) {
	// GenericOpenAPIError's fields are unexported, so the only way to build one
	// carrying a body is through the SDK's own decoding path. A response with a
	// non-2xx status and a body produces exactly that.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"\"fromDefault\" is not allowed"}`))
	}))
	defer srv.Close()
	_, _, sdkErr := newTestUserAPIClient(srv.URL).InternetAccessPoliciesAPI.
		GetAccessPolicy(context.Background()).Execute()
	if sdkErr == nil {
		t.Fatal("the fixture did not produce an SDK error")
	}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"unwrapped, as every existing call site passes it", sdkErr},
		{"wrapped once with %w, as async.go's withStatusID does",
			fmt.Errorf("re-reading the access policy: %w", sdkErr)},
		{"wrapped twice", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", sdkErr))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := appendErrorDiags(nil, "Unable to read the access policy", tc.err)
			if len(diags) != 1 {
				t.Fatalf("got %d diagnostics, want 1", len(diags))
			}
			if !strings.Contains(diags[0].Detail, "fromDefault") {
				t.Errorf("the detail is %q, which does not contain the server's message. "+
					"The operator is shown a status line instead of the reason.",
					diags[0].Detail)
			}
		})
	}
}
