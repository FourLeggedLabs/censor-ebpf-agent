package api_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FourLeggedLabs/censor-ebpf-agent/internal/api"
	"github.com/FourLeggedLabs/censor-ebpf-agent/internal/gha"
	agentv1 "github.com/FourLeggedLabs/protos/gen/go/censor/agent/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestLoadAPIKey(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "api-key")
	if err := os.WriteFile(p, []byte("  secret-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := api.LoadAPIKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if k != "secret-key" {
		t.Fatalf("got %q", k)
	}
}

func TestFetchPolicy(t *testing.T) {
	want := &agentv1.AgentPolicy{
		CorrelationId: "c1",
		Mode:          agentv1.Mode_MODE_MONITOR,
		AllowedHosts:  []string{"github.com"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agent/policy" {
			t.Fatalf("path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Fatalf("auth %q", r.Header.Get("Authorization"))
		}
		if r.URL.Query().Get("job_id") != "build:deadbeef" {
			t.Fatalf("query %v", r.URL.Query())
		}
		b, err := protojson.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)

	c := &api.Client{BaseURL: srv.URL, APIKey: "tok", Version: "dev", HTTPClient: srv.Client()}
	got, err := c.FetchPolicy(context.Background(), &gha.Context{
		Job:   "build",
		JobID: "build:deadbeef",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetCorrelationId() != "c1" || got.GetMode() != agentv1.Mode_MODE_MONITOR {
		t.Fatalf("%+v", got)
	}
}

func TestUploadLogsGzip(t *testing.T) {
	var gotMeta string
	var gotLog []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Fatal(err)
		}
		gotMeta = r.FormValue("metadata")
		f, _, err := r.FormFile("log")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		gotLog, err = io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(`{"type":"EVENT_TYPE_DNS"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	c := &api.Client{BaseURL: srv.URL, APIKey: "tok", HTTPClient: srv.Client()}
	err := c.UploadLogs(context.Background(), &agentv1.AgentLogUpload{
		CorrelationId: "c1",
		Status:        "success",
		Mode:          agentv1.Mode_MODE_ENFORCE,
	}, gz.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotMeta, "c1") {
		t.Fatalf("metadata %s", gotMeta)
	}
	gr, err := gzip.NewReader(bytes.NewReader(gotLog))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), "EVENT_TYPE_DNS") {
		t.Fatalf("log %s", plain)
	}
}
