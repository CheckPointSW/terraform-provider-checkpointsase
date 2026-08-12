package checkpointsase

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// asyncResult is the normalised shape of every v3 async status response.
// The v3 API exposes three status endpoints (/networks/status/{id},
// /networks/standard/status/{id}, /applications/status/{id}) that share this
// {completed, result:{statusCode, reason[]}} envelope.
type asyncResult struct {
	// Completed reports whether the backend finished the operation.
	Completed bool
	// StatusCode is result.statusCode. Zero means the API omitted it.
	StatusCode int
	// Reasons is result.reason, populated on failure.
	Reasons []string
}

// pollFunc fetches the current status of one async operation.
type pollFunc func(ctx context.Context) (asyncResult, *http.Response, error)

// pollAsync polls until the operation completes, fails, or ctx expires.
//
// Three things it does that the previous per-resource polling loops did not:
//
//  1. Requires a 2xx result.statusCode, not merely completed == true. The old
//     checkNetworkStatus only failed on 500, so a 400 or 409 completion was
//     reported to Terraform as success.
//  2. Retries transient errors (5xx, EOF, connection reset) within
//     transientBudget. A single transient EOF previously failed the whole
//     resource and orphaned the backend object from state.
//  3. Honours ctx, so a Terraform timeout produces a deadline error instead of
//     hanging or recording a false success.
func pollAsync(ctx context.Context, poll pollFunc, interval time.Duration, transientBudget int) error {
	remaining := transientBudget
	backoff := interval

	for {
		result, resp, err := poll(ctx)
		if err != nil {
			if classifyAPIError(resp, err) == errKindTransient && remaining > 0 {
				remaining--
				if waitErr := sleepCtx(ctx, backoff); waitErr != nil {
					return waitErr
				}
				backoff *= 2
				continue
			}
			return fmt.Errorf("polling async operation: %w", err)
		}

		if result.Completed {
			if isSuccessStatus(result.StatusCode) {
				return nil
			}
			return fmt.Errorf("async operation failed with status %d: %s",
				result.StatusCode, joinReasons(result.Reasons))
		}

		if waitErr := sleepCtx(ctx, interval); waitErr != nil {
			return waitErr
		}
	}
}

// isSuccessStatus treats 0 as success because the API omits statusCode on some
// successful completions.
func isSuccessStatus(code int) bool {
	return code == 0 || (code >= 200 && code < 300)
}

func joinReasons(reasons []string) string {
	if len(reasons) == 0 {
		return "no reason reported by the API"
	}
	return strings.Join(reasons, " | ")
}

// sleepCtx waits for d, returning ctx's error if it expires first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for the async operation to complete: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}
