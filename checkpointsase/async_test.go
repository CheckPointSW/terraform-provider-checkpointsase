package checkpointsase

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
)

const testInterval = time.Millisecond

func TestPollAsyncSucceedsOnCompletedTwoXX(t *testing.T) {
	calls := 0
	poll := func(ctx context.Context) (asyncResult, *http.Response, error) {
		calls++
		if calls < 3 {
			return asyncResult{Completed: false}, resp(200), nil
		}
		return asyncResult{Completed: true, StatusCode: 200}, resp(200), nil
	}
	if err := pollAsync(context.Background(), poll, testInterval, 2); err != nil {
		t.Fatalf("pollAsync() = %v, want nil", err)
	}
	if calls != 3 {
		t.Errorf("poll called %d times, want 3", calls)
	}
}

func TestPollAsyncTreatsMissingStatusCodeAsSuccess(t *testing.T) {
	poll := func(ctx context.Context) (asyncResult, *http.Response, error) {
		return asyncResult{Completed: true, StatusCode: 0}, resp(200), nil
	}
	if err := pollAsync(context.Background(), poll, testInterval, 2); err != nil {
		t.Fatalf("pollAsync() = %v, want nil (0 means the API omitted the field)", err)
	}
}

// The defect this function exists to fix: the old checkNetworkStatus only
// failed on 500, so a 409 completion was reported as success.
func TestPollAsyncFailsOnCompletedNonTwoXX(t *testing.T) {
	poll := func(ctx context.Context) (asyncResult, *http.Response, error) {
		return asyncResult{
			Completed:  true,
			StatusCode: 409,
			Reasons:    []string{"subnet overlaps an existing network"},
		}, resp(200), nil
	}
	err := pollAsync(context.Background(), poll, testInterval, 2)
	if err == nil {
		t.Fatal("pollAsync() = nil, want an error for a 409 completion")
	}
	if !strings.Contains(err.Error(), "subnet overlaps an existing network") {
		t.Errorf("error %q should include the API's reason", err)
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("error %q should include the status code", err)
	}
}

func TestPollAsyncRetriesTransientErrorsWithinBudget(t *testing.T) {
	calls := 0
	poll := func(ctx context.Context) (asyncResult, *http.Response, error) {
		calls++
		if calls <= 2 {
			return asyncResult{}, nil, io.ErrUnexpectedEOF
		}
		return asyncResult{Completed: true, StatusCode: 200}, resp(200), nil
	}
	if err := pollAsync(context.Background(), poll, testInterval, 2); err != nil {
		t.Fatalf("pollAsync() = %v, want nil after 2 transient errors within budget", err)
	}
	if calls != 3 {
		t.Errorf("poll called %d times, want 3", calls)
	}
}

func TestPollAsyncFailsWhenTransientBudgetExhausted(t *testing.T) {
	poll := func(ctx context.Context) (asyncResult, *http.Response, error) {
		return asyncResult{}, nil, io.ErrUnexpectedEOF
	}
	err := pollAsync(context.Background(), poll, testInterval, 2)
	if err == nil {
		t.Fatal("pollAsync() = nil, want an error once the transient budget is spent")
	}
	if !strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("error %q should retain the underlying cause", err)
	}
}

func TestPollAsyncDoesNotRetryNonTransientErrors(t *testing.T) {
	calls := 0
	poll := func(ctx context.Context) (asyncResult, *http.Response, error) {
		calls++
		return asyncResult{}, resp(http.StatusBadRequest), errors.New("bad request")
	}
	if err := pollAsync(context.Background(), poll, testInterval, 5); err == nil {
		t.Fatal("pollAsync() = nil, want an error for a 400")
	}
	if calls != 1 {
		t.Errorf("poll called %d times, want 1 — a 400 must not be retried", calls)
	}
}

func TestPollAsyncHonoursContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	poll := func(ctx context.Context) (asyncResult, *http.Response, error) {
		return asyncResult{Completed: false}, resp(200), nil
	}
	err := pollAsync(ctx, poll, 5*time.Millisecond, 2)
	if err == nil {
		t.Fatal("pollAsync() = nil, want a deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v should wrap context.DeadlineExceeded", err)
	}
}

// TestPollAsyncReturnsPromptlyOnAlreadyCancelledContext covers the half of
// ctx handling that TestPollAsyncHonoursContextDeadline (above) does not: a
// context cancelled *before* pollAsync is ever invoked — the shape a
// Terraform SIGINT/Ctrl-C produces once ctx propagates all the way down from
// the CRUD entry point — rather than one that expires mid-poll. pollAsync
// must observe the cancellation via sleepCtx's ctx.Done() case and return
// immediately, without calling poll a second time.
//
// This test would have passed in isolation even before the ctx-propagation
// fix in this change: pollAsync itself always honoured ctx correctly. What
// was broken is that every CRUD entry point reassigned ctx to
// context.Background() before calling down into this code, so a cancelled
// or deadlined Terraform context could never reach here in production. That
// is exactly why this gap needed a test written against the real call
// path (not just pollAsync in isolation) to be caught earlier.
func TestPollAsyncReturnsPromptlyOnAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before pollAsync is ever called

	calls := 0
	poll := func(ctx context.Context) (asyncResult, *http.Response, error) {
		calls++
		return asyncResult{Completed: false}, resp(200), nil
	}

	err := pollAsync(ctx, poll, 20*time.Millisecond, 2)
	if err == nil {
		t.Fatal("pollAsync() = nil, want an error for an already-cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v should wrap context.Canceled", err)
	}
	if calls != 1 {
		t.Errorf("poll called %d times, want 1 — pollAsync must not call poll again once it observes the cancellation", calls)
	}
}

// TestAsyncFailedErrorMessage pins asyncFailedError's Error() string to the
// exact text pollAsync produced before it existed as a typed error. Every
// other test in this file that asserts on substrings of a pollAsync /
// pollStandardNetworkStatus / pollApplicationStatusForResource error message
// depends on this string staying put.
func TestAsyncFailedErrorMessage(t *testing.T) {
	err := &asyncFailedError{StatusCode: 409, Reasons: []string{"subnet overlaps an existing network"}}
	want := "async operation failed with status 409: subnet overlaps an existing network"
	if got := err.Error(); got != want {
		t.Errorf("asyncFailedError.Error() = %q, want %q", got, want)
	}
}

// TestPollAsyncFailsOnCompletedNonTwoXX (above) already checks the message
// text; this checks that the error pollAsync returns for a completed-but-failed
// operation is specifically an *asyncFailedError carrying the status code, so
// callers (isAsyncConflict, and eventually the adopt-on-failure sites) can
// branch on it via errors.As instead of parsing the message.
func TestPollAsyncReturnsAsyncFailedErrorOnCompletedNonTwoXX(t *testing.T) {
	poll := func(ctx context.Context) (asyncResult, *http.Response, error) {
		return asyncResult{
			Completed:  true,
			StatusCode: 409,
			Reasons:    []string{"name already in use"},
		}, resp(200), nil
	}
	err := pollAsync(context.Background(), poll, testInterval, 2)
	var failed *asyncFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("pollAsync() error = %v (%T), want an *asyncFailedError", err, err)
	}
	if failed.StatusCode != 409 {
		t.Errorf("asyncFailedError.StatusCode = %d, want 409", failed.StatusCode)
	}
}

func TestIsAsyncConflict(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "409 conflict",
			err:  &asyncFailedError{StatusCode: 409, Reasons: []string{"name already in use"}},
			want: true,
		},
		{
			name: "500 completed failure is not a conflict",
			err:  &asyncFailedError{StatusCode: 500, Reasons: []string{"internal server error"}},
			want: false,
		},
		{
			name: "transport error is not a conflict",
			err:  io.ErrUnexpectedEOF,
			want: false,
		},
		{
			name: "nil error is not a conflict",
			err:  nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAsyncConflict(tt.err); got != tt.want {
				t.Errorf("isAsyncConflict(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestPollUntilConvergedSucceedsOnFirstPoll covers the case a poll that is
// unnecessary in principle but harmless in practice: the predicate is
// already true on the very first read.
func TestPollUntilConvergedSucceedsOnFirstPoll(t *testing.T) {
	calls := 0
	poll := func(ctx context.Context) (bool, *http.Response, error) {
		calls++
		return true, resp(200), nil
	}
	if err := pollUntilConverged(context.Background(), poll, testInterval, 2, "thing to converge"); err != nil {
		t.Fatalf("pollUntilConverged() = %v, want nil", err)
	}
	if calls != 1 {
		t.Errorf("poll called %d times, want 1", calls)
	}
}

// TestPollUntilConvergedSucceedsOnLaterPoll is the shape both call sites hit
// in production: the write already returned, but the object it changed is
// not observable on the list/get endpoint for a couple of reads afterwards.
func TestPollUntilConvergedSucceedsOnLaterPoll(t *testing.T) {
	calls := 0
	poll := func(ctx context.Context) (bool, *http.Response, error) {
		calls++
		return calls >= 3, resp(200), nil
	}
	if err := pollUntilConverged(context.Background(), poll, testInterval, 2, "thing to converge"); err != nil {
		t.Fatalf("pollUntilConverged() = %v, want nil", err)
	}
	if calls != 3 {
		t.Errorf("poll called %d times, want 3", calls)
	}
}

// TestPollUntilConvergedHonoursContextDeadline is the case a caller-side bug
// (or a backend that never converges) must not hang Terraform forever: the
// predicate never turns true, so pollUntilConverged must give up once ctx
// expires, and the error must name the awaited condition and wrap
// context.DeadlineExceeded so callers can distinguish it from other failures.
func TestPollUntilConvergedHonoursContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	poll := func(ctx context.Context) (bool, *http.Response, error) {
		return false, resp(200), nil
	}
	err := pollUntilConverged(ctx, poll, 5*time.Millisecond, 2, "region us-east to appear in network net-123")
	if err == nil {
		t.Fatal("pollUntilConverged() = nil, want a deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error %v should wrap context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "region us-east to appear in network net-123") {
		t.Errorf("error %q should name what it was waiting for", err)
	}
}

// TestPollUntilConvergedRetriesTransientErrorsWithinBudget mirrors
// TestPollAsyncRetriesTransientErrorsWithinBudget: a blip on the list/get
// read must not fail the whole wait if it clears within the budget.
func TestPollUntilConvergedRetriesTransientErrorsWithinBudget(t *testing.T) {
	calls := 0
	poll := func(ctx context.Context) (bool, *http.Response, error) {
		calls++
		if calls <= 2 {
			return false, nil, io.ErrUnexpectedEOF
		}
		return true, resp(200), nil
	}
	if err := pollUntilConverged(context.Background(), poll, testInterval, 2, "thing to converge"); err != nil {
		t.Fatalf("pollUntilConverged() = %v, want nil after 2 transient errors within budget", err)
	}
	if calls != 3 {
		t.Errorf("poll called %d times, want 3", calls)
	}
}

// TestPollUntilConvergedFailsWhenTransientBudgetExhausted mirrors
// TestPollAsyncFailsWhenTransientBudgetExhausted: once the budget for
// transient blips is spent, pollUntilConverged must fail rather than retry
// forever, and the error must still name what it was waiting for.
func TestPollUntilConvergedFailsWhenTransientBudgetExhausted(t *testing.T) {
	poll := func(ctx context.Context) (bool, *http.Response, error) {
		return false, nil, io.ErrUnexpectedEOF
	}
	err := pollUntilConverged(context.Background(), poll, testInterval, 2, "gateway removal to take effect")
	if err == nil {
		t.Fatal("pollUntilConverged() = nil, want an error once the transient budget is spent")
	}
	if !strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("error %q should retain the underlying cause", err)
	}
	if !strings.Contains(err.Error(), "gateway removal to take effect") {
		t.Errorf("error %q should name what it was waiting for", err)
	}
}

// TestPollUntilConvergedDoesNotRetryNonTransientErrors mirrors
// TestPollAsyncDoesNotRetryNonTransientErrors: a non-transient error (e.g. a
// 400) must fail immediately, not be retried under the transient budget.
func TestPollUntilConvergedDoesNotRetryNonTransientErrors(t *testing.T) {
	calls := 0
	poll := func(ctx context.Context) (bool, *http.Response, error) {
		calls++
		return false, resp(http.StatusBadRequest), errors.New("bad request")
	}
	if err := pollUntilConverged(context.Background(), poll, testInterval, 5, "thing to converge"); err == nil {
		t.Fatal("pollUntilConverged() = nil, want an error for a 400")
	}
	if calls != 1 {
		t.Errorf("poll called %d times, want 1 — a 400 must not be retried", calls)
	}
}

// standardNetworkStatusServer stands up a fake standard-networks status
// endpoint that always answers with body on the first request, so
// pollStandardNetworkStatus never has to sleep between polls.
func standardNetworkStatusServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

// This is the falsifiable proof of the migration: checkNetworkStatus's old
// semantics (fail only on statusCode 500) would report this 409 completion
// as a successful apply. pollStandardNetworkStatus must not.
func TestPollStandardNetworkStatusFailsOnCompletedNonTwoXX(t *testing.T) {
	server := standardNetworkStatusServer(t, `{"completed":true,"result":{"statusCode":409,"reason":["subnet overlaps an existing network"]}}`)

	client := perimeter81Sdk.NewAPIClient(perimeter81Sdk.NewConfiguration("test-key", server.URL))

	err := pollStandardNetworkStatus(context.Background(), client, "status-id", testInterval)
	if err == nil {
		t.Fatal("pollStandardNetworkStatus() = nil, want an error for a 409 completion")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("error %q should include the status code", err)
	}
	if !strings.Contains(err.Error(), "subnet overlaps an existing network") {
		t.Errorf("error %q should include the API's reason", err)
	}
}

// Companion case: a completed + 200 response must return nil, so the test
// above cannot pass by having pollStandardNetworkStatus always error.
func TestPollStandardNetworkStatusSucceedsOnCompletedTwoHundred(t *testing.T) {
	server := standardNetworkStatusServer(t, `{"completed":true,"result":{"statusCode":200}}`)

	client := perimeter81Sdk.NewAPIClient(perimeter81Sdk.NewConfiguration("test-key", server.URL))

	if err := pollStandardNetworkStatus(context.Background(), client, "status-id", testInterval); err != nil {
		t.Fatalf("pollStandardNetworkStatus() = %v, want nil for a completed 200 response", err)
	}
}

// pollStandardNetworkStatusForResource is what create paths use to learn the
// new object's ID. A silent regression that dropped result.resource would
// leave those paths writing an empty ID to state without any test catching it.
func TestPollStandardNetworkStatusForResourceReturnsResourceOnCompletedTwoHundred(t *testing.T) {
	server := standardNetworkStatusServer(t, `{"completed":true,"result":{"statusCode":200,"resource":"/networks/standard/net-123"}}`)

	client := perimeter81Sdk.NewAPIClient(perimeter81Sdk.NewConfiguration("test-key", server.URL))

	resource, err := pollStandardNetworkStatusForResource(context.Background(), client, "status-id", testInterval)
	if err != nil {
		t.Fatalf("pollStandardNetworkStatusForResource() error = %v, want nil for a completed 200 response", err)
	}
	if resource != "/networks/standard/net-123" {
		t.Errorf("pollStandardNetworkStatusForResource() resource = %q, want %q", resource, "/networks/standard/net-123")
	}
}

// applicationStatusServer stands up a fake applications status endpoint that
// always answers with body on the first request, so
// pollApplicationStatusForResource never has to sleep between polls.
func applicationStatusServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

// This is the falsifiable proof of the migration: the old resourceApplicationCreate
// loop checked only GetCompleted() and never inspected result.statusCode, so a
// 409 completion fell through to the list-by-name fallback instead of failing
// the apply. pollApplicationStatusForResource must not.
func TestPollApplicationStatusFailsOnCompletedNonTwoXX(t *testing.T) {
	server := applicationStatusServer(t, `{"completed":true,"result":{"statusCode":409,"reason":["application with this name already exists"]}}`)

	client := perimeter81Sdk.NewAPIClient(perimeter81Sdk.NewConfiguration("test-key", server.URL))

	_, err := pollApplicationStatusForResource(context.Background(), client, "status-id", testInterval)
	if err == nil {
		t.Fatal("pollApplicationStatusForResource() error = nil, want an error for a 409 completion")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("error %q should include the status code", err)
	}
	if !strings.Contains(err.Error(), "application with this name already exists") {
		t.Errorf("error %q should include the API's reason", err)
	}
}

// Companion case: a completed + 200 response carrying a resource must return
// it with a nil error, so the test above cannot pass by having
// pollApplicationStatusForResource always error.
func TestPollApplicationStatusForResourceReturnsResourceOnCompletedTwoHundred(t *testing.T) {
	server := applicationStatusServer(t, `{"completed":true,"result":{"statusCode":200,"resource":"/applications/app-123"}}`)

	client := perimeter81Sdk.NewAPIClient(perimeter81Sdk.NewConfiguration("test-key", server.URL))

	resource, err := pollApplicationStatusForResource(context.Background(), client, "status-id", testInterval)
	if err != nil {
		t.Fatalf("pollApplicationStatusForResource() error = %v, want nil for a completed 200 response", err)
	}
	if resource != "/applications/app-123" {
		t.Errorf("pollApplicationStatusForResource() resource = %q, want %q", resource, "/applications/app-123")
	}
}
