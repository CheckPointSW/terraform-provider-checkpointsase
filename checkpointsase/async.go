package checkpointsase

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	perimeter81Sdk "github.com/CheckPointSW/perimeter-81-client-sdk/v3"
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
//  1. Requires a 2xx result.statusCode, not merely completed == true.
//     checkNetworkStatus, the per-resource polling helper this replaced, only
//     failed on 500, so a 400 or 409 completion was reported to Terraform as
//     success.
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
			return &asyncFailedError{StatusCode: result.StatusCode, Reasons: result.Reasons}
		}

		if waitErr := sleepCtx(ctx, interval); waitErr != nil {
			return waitErr
		}
	}
}

// asyncFailedError is returned when the backend completes an operation with a
// non-2xx status. It carries the status code so callers can distinguish a
// conflict -- where recovery by name lookup would adopt someone else's object --
// from a transient or server-side failure.
type asyncFailedError struct {
	StatusCode int
	Reasons    []string
}

func (e *asyncFailedError) Error() string {
	return fmt.Sprintf("async operation failed with status %d: %s",
		e.StatusCode, joinReasons(e.Reasons))
}

// isAsyncConflict reports whether err is an async completion the server refused
// as a conflict (409). Adoption-by-name is never safe in that case: the
// conflicting object is exactly what a name lookup will find.
//
// Delegates to classifyAPIError so the conflict definition stays in one
// place (errKindConflict, currently 409 only) instead of being re-decided here.
func isAsyncConflict(err error) bool {
	var failed *asyncFailedError
	if !errors.As(err, &failed) {
		return false
	}
	return classifyAPIError(&http.Response{StatusCode: failed.StatusCode}, err) == errKindConflict
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

const (
	// standardNetworkPollInterval is the cadence the network create/update
	// loops used before this migration.
	standardNetworkPollInterval = 60 * time.Second
	// standardTunnelPollInterval is the cadence the tunnel loops used. It is
	// deliberately different from the network cadence: preserving each call
	// site's original timing keeps this migration a correctness-only change.
	standardTunnelPollInterval = 20 * time.Second
	// standardNetworkTransientBudget allows two 5xx/EOF blips per operation.
	standardNetworkTransientBudget = 2
	// applicationPollInterval is the cadence resourceApplicationCreate used before
	// this migration.
	applicationPollInterval = 30 * time.Second
	// applicationTransientBudget allows two 5xx/EOF blips per operation.
	applicationTransientBudget = 2
)

// pollStandardNetworkStatusForResource polls the standard-networks async status
// endpoint and additionally returns result.resource, which create paths need in
// order to learn the new object's ID.
//
// pollAsync returns only an error, so the resource is captured from the closure
// on the completing poll rather than threaded through asyncResult.
//
// The returned resource string is meaningful only when err is nil: a
// completed-but-failed status (e.g. a 409) can still carry a non-empty
// result.resource, so callers must not derive an ID from it on the error path.
func pollStandardNetworkStatusForResource(ctx context.Context, client *perimeter81Sdk.APIClient, statusId string, interval time.Duration) (string, error) {
	var resource string
	err := pollAsync(ctx, func(ctx context.Context) (asyncResult, *http.Response, error) {
		status, resp, err := client.StandardNetworksAPI.StandardNetworksControllerV2Status(ctx, statusId).Execute()
		if err != nil {
			return asyncResult{}, resp, err
		}
		out := asyncResult{Completed: status.GetCompleted()}
		if r := status.Result; r != nil {
			out.StatusCode = int(r.GetStatusCode())
			out.Reasons = r.GetReason()
			resource = r.GetResource()
		}
		return out, resp, nil
	}, interval, standardNetworkTransientBudget)
	return resource, err
}

// pollStandardNetworkStatus polls the standard-networks async status endpoint
// until the operation completes, fails, or ctx expires, discarding the result
// resource. Use pollStandardNetworkStatusForResource when the caller needs the
// created object's ID.
//
// It replaced checkNetworkStatus, which failed only on statusCode 500 and so
// reported a 400 or 409 completion to Terraform as a successful apply.
func pollStandardNetworkStatus(ctx context.Context, client *perimeter81Sdk.APIClient, statusId string, interval time.Duration) error {
	_, err := pollStandardNetworkStatusForResource(ctx, client, statusId, interval)
	return err
}

// pollApplicationStatusForResource polls the applications async status
// endpoint and additionally returns result.resource, which the create path
// needs in order to learn the new application's ID.
//
// pollAsync returns only an error, so the resource is captured from the
// closure on the completing poll rather than threaded through asyncResult.
//
// The returned resource string is meaningful only when err is nil: a
// completed-but-failed status (e.g. a 409) can still carry a non-empty
// result.resource, so callers must not derive an ID from it on the error path.
func pollApplicationStatusForResource(ctx context.Context, client *perimeter81Sdk.APIClient, statusId string, interval time.Duration) (string, error) {
	var resource string
	err := pollAsync(ctx, func(ctx context.Context) (asyncResult, *http.Response, error) {
		status, resp, err := client.ApplicationsAPI.GetApplicationStatus(ctx, statusId).Execute()
		if err != nil {
			return asyncResult{}, resp, err
		}
		out := asyncResult{Completed: status.GetCompleted()}
		if r := status.Result; r != nil {
			out.StatusCode = int(r.GetStatusCode())
			out.Reasons = r.GetReason()
			resource = r.GetResource()
		}
		return out, resp, nil
	}, interval, applicationTransientBudget)
	return resource, err
}
