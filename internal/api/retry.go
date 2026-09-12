package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"time"
)

// FailureClass classifies API errors for retry / posture decisions.
type FailureClass int

const (
	FailureNone FailureClass = iota
	FailureTransport
	FailureServer   // 5xx, 429
	FailureClient   // 4xx other than retryable
	FailureAuth     // 401, 403
	FailureNotFound // 404
)

func (c FailureClass) Retryable() bool {
	return c == FailureTransport || c == FailureServer
}

// ClassifyStatus maps an HTTP status to a failure class.
func ClassifyStatus(code int) FailureClass {
	switch code {
	case http.StatusOK, http.StatusNoContent, http.StatusCreated, http.StatusAccepted:
		return FailureNone
	case http.StatusUnauthorized, http.StatusForbidden:
		return FailureAuth
	case http.StatusNotFound:
		return FailureNotFound
	case http.StatusTooManyRequests, http.StatusRequestTimeout:
		return FailureServer
	}
	if code >= 500 {
		return FailureServer
	}
	if code >= 400 {
		return FailureClient
	}
	return FailureServer
}

// APIError is a classified HTTP/API failure.
type APIError struct {
	Class      FailureClass
	StatusCode int
	Err        error
}

func (e *APIError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("api error class=%d status=%d: %v", e.Class, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("api error class=%d: %v", e.Class, e.Err)
}

func (e *APIError) Unwrap() error { return e.Err }

func withRetries(ctx context.Context, attempts int, fn func(context.Context) error) error {
	if attempts < 1 {
		attempts = 3
	}
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			backoff := time.Duration(100*(1<<i))*time.Millisecond + time.Duration(rand.IntN(50))*time.Millisecond
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
		err := fn(ctx)
		if err == nil {
			return nil
		}
		last = err
		var ae *APIError
		if errors.As(err, &ae) && !ae.Class.Retryable() {
			return err
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	return last
}

func mapDoError(err error) error {
	if err == nil {
		return nil
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return &APIError{Class: FailureTransport, Err: err}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return &APIError{Class: FailureTransport, Err: err}
	}
	return &APIError{Class: FailureTransport, Err: err}
}
