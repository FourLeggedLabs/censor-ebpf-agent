package githubhosts_test

import (
	"testing"

	"github.com/FourLeggedLabs/censor-ebpf-agent/internal/githubhosts"
	"github.com/FourLeggedLabs/censor-ebpf-agent/internal/policy"
)

func TestMergeAllowed(t *testing.T) {
	got := githubhosts.MergeAllowed(true, []string{"registry.npmjs.org", "github.com"})
	if len(got) < len(githubhosts.DefaultHosts) {
		t.Fatalf("len %d", len(got))
	}
	// user host present
	found := false
	for _, h := range got {
		if h == "registry.npmjs.org" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing user host")
	}
	// no duplicate github.com
	n := 0
	for _, h := range got {
		if h == "github.com" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("github.com count %d", n)
	}
}

func TestDefaultHostsMatchAPI(t *testing.T) {
	allowed := githubhosts.MergeAllowed(true, nil)
	if !policy.MatchHost(allowed[0], "github.com") && !policy.EvaluateHost(allowed, nil, "api.github.com").Allow {
		t.Fatal("api.github.com should allow")
	}
	d := policy.EvaluateHost(allowed, nil, "api.github.com")
	if !d.Allow {
		t.Fatalf("%+v", d)
	}
	d = policy.EvaluateHost(allowed, nil, "raw.githubusercontent.com")
	if !d.Allow {
		t.Fatalf("githubusercontent: %+v", d)
	}
}
