package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestRateLimitRetrySucceeds verifies that the connector retries after a 429
// and succeeds on the second attempt.
func TestRateLimitRetrySucceeds(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			// First request: return 429 with no reset header (use exponential backoff).
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		// Second request: success with one entry.
		w.Header().Set("Content-Type", "application/json")
		entries := []map[string]interface{}{
			{"action": "repo.create", "actor": "testuser", "created_at": float64(time.Now().UnixMilli())},
		}
		json.NewEncoder(w).Encode(entries)
	}))
	defer srv.Close()

	conn := &connector{
		client:         srv.Client(),
		org:            "testorg",
		maxPages:       1,
		retryBaseDelay: time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := conn.getWithRetry(ctx, srv.URL+"/test", url.Values{"per_page": []string{"100"}})
	if err != nil {
		t.Fatalf("getWithRetry: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

// TestRateLimitRetryWithResetHeader verifies that the connector reads
// the X-RateLimit-Reset header to determine wait time.
func TestRateLimitRetryWithResetHeader(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			// Return 429 with a reset header 1 second in the future.
			w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Millisecond).Unix()))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
	}))
	defer srv.Close()

	conn := &connector{client: srv.Client(), org: "testorg", retryBaseDelay: time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := conn.getWithRetry(ctx, srv.URL+"/test", nil)
	if err != nil {
		t.Fatalf("getWithRetry: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

// TestRateLimitExhaustsRetries verifies that the connector gives up after
// maxRetries consecutive 429 responses and returns an error.
func TestRateLimitExhaustsRetries(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	conn := &connector{client: srv.Client(), org: "testorg", retryBaseDelay: time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := conn.getWithRetry(ctx, srv.URL+"/test", nil)
	if err == nil {
		t.Fatal("expected error after exhausting retries, got nil")
	}
	if !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("unexpected error message: %v", err)
	}
	// Should have tried maxRetries+1 times total (initial + maxRetries retries).
	expected := maxRetries + 1
	if attempts != expected {
		t.Errorf("expected %d attempts, got %d", expected, attempts)
	}
}

// TestRateLimitContextCancel verifies that the connector respects context
// cancellation during the backoff wait.
func TestRateLimitContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always 429 with a far-future reset header so the wait is long.
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Hour).Unix()))
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	conn := &connector{client: srv.Client(), org: "testorg"}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := conn.getWithRetry(ctx, srv.URL+"/test", nil)
	if err == nil {
		t.Fatal("expected error after context cancel, got nil")
	}
	// Should be a context error, not a rate limit error.
	if !strings.Contains(err.Error(), "context") && err.Error() != context.DeadlineExceeded.Error() {
		// Accept either context deadline or context canceled.
		if err != context.DeadlineExceeded && err != context.Canceled {
			t.Errorf("unexpected error: %v", err)
		}
	}
}
