package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FourLeggedLabs/censor-ebpf-agent/internal/api"
	"github.com/FourLeggedLabs/censor-ebpf-agent/internal/gha"
	agentv1 "github.com/FourLeggedLabs/protos/gen/go/censor/agent/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestUploadRetriesThenSucceeds(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	c := &api.Client{BaseURL: srv.URL, APIKey: "tok", HTTPClient: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := c.UploadLogs(ctx, &agentv1.AgentLogUpload{CorrelationId: "c", Status: "success"}, []byte{0x1f, 0x8b})
	if err != nil {
		t.Fatal(err)
	}
	if n.Load() < 3 {
		t.Fatalf("attempts %d", n.Load())
	}
}

func TestFetchPolicyNoRetryOn404(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	c := &api.Client{BaseURL: srv.URL, APIKey: "tok", HTTPClient: srv.Client()}
	_, err := c.FetchPolicy(context.Background(), &gha.Context{Job: "j"})
	if err == nil {
		t.Fatal("expected error")
	}
	var ae *api.APIError
	if !errors.As(err, &ae) || ae.Class != api.FailureNotFound {
		t.Fatalf("%v", err)
	}
	if n.Load() != 1 {
		t.Fatalf("should not retry 404, attempts=%d", n.Load())
	}
}

func TestFetchPolicyOK(t *testing.T) {
	pol := &agentv1.AgentPolicy{CorrelationId: "x", Mode: agentv1.Mode_MODE_MONITOR}
	b, _ := protojson.Marshal(pol)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	c := &api.Client{BaseURL: srv.URL, APIKey: "tok", HTTPClient: srv.Client()}
	got, err := c.FetchPolicy(context.Background(), &gha.Context{})
	if err != nil || got.GetCorrelationId() != "x" {
		t.Fatalf("%v %+v", err, got)
	}
}
