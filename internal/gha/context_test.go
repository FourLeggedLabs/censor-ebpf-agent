package gha_test

import (
	"os"
	"testing"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/gha"
)

func TestJobIDStable(t *testing.T) {
	m := map[string]any{"os": "ubuntu", "go": "1.27"}
	a := gha.JobID("build", m)
	b := gha.JobID("build", map[string]any{"go": "1.27", "os": "ubuntu"})
	if a != b {
		t.Fatalf("unstable job id: %q vs %q", a, b)
	}
	if a == "build" || len(a) < len("build:")+12 {
		t.Fatalf("expected hashed suffix, got %q", a)
	}
	if gha.JobID("build", nil) != "build" {
		t.Fatal("empty matrix should be job name only")
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "FourLeggedLabs/censor")
	t.Setenv("GITHUB_JOB", "test")
	t.Setenv("GITHUB_RUN_ID", "99")
	t.Setenv("CENSOR_MATRIX", `{"os":"ubuntu-latest"}`)
	os.Unsetenv("GITHUB_REPOSITORY_OWNER")

	c, err := gha.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.RepoOwner != "FourLeggedLabs" || c.RepoName != "censor" {
		t.Fatalf("repo: %+v", c)
	}
	if c.JobID == "test" {
		t.Fatalf("expected matrix in job id, got %q", c.JobID)
	}
	jc, err := c.Proto()
	if err != nil {
		t.Fatal(err)
	}
	if jc.GetJobId() != c.JobID {
		t.Fatal(jc.GetJobId())
	}
}
