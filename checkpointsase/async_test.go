package checkpointsase

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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
