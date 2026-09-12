package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/gha"
	agentv1 "github.com/FourLeggedLabs/protos/gen/go/censor/agent/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	defaultAPIKeyPath = "/etc/censor/api-key"
	policyPath        = "/v1/agent/policy"
	logsPath          = "/v1/agent/logs"
)

// Client talks to the Censor API using protojson payloads.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
	Version    string
}

// LoadAPIKey reads the static API key from path (default /etc/censor/api-key).
func LoadAPIKey(path string) (string, error) {
	if path == "" {
		path = defaultAPIKeyPath
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// FetchPolicy GETs AgentPolicy for the current GHA context.
func (c *Client) FetchPolicy(ctx context.Context, ghac *gha.Context) (*agentv1.AgentPolicy, error) {
	u, err := url.Parse(strings.TrimRight(c.BaseURL, "/") + policyPath)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("repo_owner", ghac.RepoOwner)
	set("repo_name", ghac.RepoName)
	set("workflow", ghac.Workflow)
	set("workflow_ref", ghac.WorkflowRef)
	set("run_id", ghac.RunID)
	set("run_attempt", ghac.RunAttempt)
	set("job", ghac.Job)
	set("job_id", ghac.JobID)
	set("sha", ghac.SHA)
	set("ref", ghac.Ref)
	set("actor", ghac.Actor)
	set("event_name", ghac.EventName)
	set("runner_arch", ghac.RunnerArch)
	set("runner_os", ghac.RunnerOS)
	set("matrix", ghac.MatrixJSON)
	set("agent_version", c.Version)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Accept", "application/json")

	res, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy fetch: status %d: %s", res.StatusCode, truncate(body, 256))
	}
	pol := &agentv1.AgentPolicy{}
	if err := protojson.Unmarshal(body, pol); err != nil {
		return nil, fmt.Errorf("policy decode: %w", err)
	}
	return pol, nil
}

// UploadLogs POSTs multipart metadata (AgentLogUpload) + gzipped NDJSON log.
func (c *Client) UploadLogs(ctx context.Context, meta *agentv1.AgentLogUpload, gzipLog []byte) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	mb, err := protojson.Marshal(meta)
	if err != nil {
		return err
	}
	if err := w.WriteField("metadata", string(mb)); err != nil {
		return err
	}
	logPart, err := w.CreateFormFile("log", "agent.ndjson.gz")
	if err != nil {
		return err
	}
	if _, err := logPart.Write(gzipLog); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	u := strings.TrimRight(c.BaseURL, "/") + logsPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", w.FormDataContentType())

	res, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 512))
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("log upload: status %d: %s", res.StatusCode, truncate(body, 256))
	}
	return nil
}

func (c *Client) http() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}
