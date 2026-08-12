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
