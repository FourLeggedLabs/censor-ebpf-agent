package gha

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

	agentv1 "github.com/FourLeggedLabs/protos/gen/go/censor/agent/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

// Context holds GitHub Actions environment used for policy fetch and log upload.
type Context struct {
	RepoOwner   string
	RepoName    string
	Workflow    string
	WorkflowRef string
	RunID       string
	RunAttempt  string
	Job         string
	JobID       string
	SHA         string
	Ref         string
	Actor       string
	EventName   string
	RunnerArch  string
	RunnerOS    string
	MatrixJSON  string // raw CENSOR_MATRIX
	Matrix      map[string]any
}

// FromEnv reads GITHUB_* / RUNNER_* / CENSOR_MATRIX from the environment.
func FromEnv() (*Context, error) {
	repo := os.Getenv("GITHUB_REPOSITORY")
	owner := os.Getenv("GITHUB_REPOSITORY_OWNER")
	name := ""
	if repo != "" {
		parts := strings.SplitN(repo, "/", 2)
		if owner == "" && len(parts) > 0 {
			owner = parts[0]
		}
		if len(parts) == 2 {
			name = parts[1]
		}
	}
	c := &Context{
		RepoOwner:   owner,
		RepoName:    name,
		Workflow:    os.Getenv("GITHUB_WORKFLOW"),
		WorkflowRef: os.Getenv("GITHUB_WORKFLOW_REF"),
		RunID:       os.Getenv("GITHUB_RUN_ID"),
		RunAttempt:  os.Getenv("GITHUB_RUN_ATTEMPT"),
		Job:         os.Getenv("GITHUB_JOB"),
		SHA:         os.Getenv("GITHUB_SHA"),
		Ref:         os.Getenv("GITHUB_REF"),
		Actor:       os.Getenv("GITHUB_ACTOR"),
		EventName:   os.Getenv("GITHUB_EVENT_NAME"),
		RunnerArch:  os.Getenv("RUNNER_ARCH"),
		RunnerOS:    os.Getenv("RUNNER_OS"),
		MatrixJSON:  strings.TrimSpace(os.Getenv("CENSOR_MATRIX")),
	}
	if c.MatrixJSON != "" && c.MatrixJSON != "{}" && c.MatrixJSON != "null" {
		var m map[string]any
		if err := json.Unmarshal([]byte(c.MatrixJSON), &m); err != nil {
			return nil, err
		}
		c.Matrix = m
	}
	c.JobID = JobID(c.Job, c.Matrix)
	return c, nil
}

// JobID returns GITHUB_JOB, or "{job}:{12-hex}" when matrix is non-empty.
func JobID(job string, matrix map[string]any) string {
	if len(matrix) == 0 {
		return job
	}
	b, err := json.Marshal(matrix)
	if err != nil {
		return job
	}
	// Canonical-ish: re-marshal via map iteration is unstable; sort via encoding/json
	// of a sorted structure — use json.Marshal on map (Go randomizes keys). For
	// stability, marshal with encoding/json after sorting keys.
	canon, err := canonicalJSON(matrix)
	if err != nil {
		sum := sha256.Sum256(b)
		return job + ":" + hex.EncodeToString(sum[:6])
	}
	sum := sha256.Sum256(canon)
	return job + ":" + hex.EncodeToString(sum[:6])
}

func canonicalJSON(v any) ([]byte, error) {
	// json.Marshal is enough if we normalize maps by sorting keys recursively.
	norm, err := normalize(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(norm)
}

func normalize(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// insertion sort to avoid importing sort just for tiny maps — use sort.Strings
		sortStrings(keys)
		// Represent as slice of pairs for stable marshal? Better: rebuild with sorted
		// marshal manually.
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			vb, err := canonicalJSON(t[k])
			if err != nil {
				return nil, err
			}
			b.Write(kb)
			b.WriteByte(':')
			b.Write(vb)
		}
		b.WriteByte('}')
		return json.RawMessage(b.String()), nil
	case []any:
		out := make([]any, len(t))
		for i := range t {
			n, err := normalize(t[i])
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	default:
		return v, nil
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Proto converts to agentv1.JobContext.
func (c *Context) Proto() (*agentv1.JobContext, error) {
	jc := &agentv1.JobContext{
		RepoOwner:   c.RepoOwner,
		RepoName:    c.RepoName,
		Workflow:    c.Workflow,
		WorkflowRef: c.WorkflowRef,
		RunId:       c.RunID,
		RunAttempt:  c.RunAttempt,
		Job:         c.Job,
		JobId:       c.JobID,
		Sha:         c.SHA,
		Ref:         c.Ref,
		Actor:       c.Actor,
		EventName:   c.EventName,
		RunnerArch:  c.RunnerArch,
		RunnerOs:    c.RunnerOS,
	}
	if len(c.Matrix) > 0 {
		s, err := structpb.NewStruct(c.Matrix)
		if err != nil {
			return nil, err
		}
		jc.Matrix = s
	}
	return jc, nil
}
