package policy_test

import (
	"testing"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/policy"
)

func TestMatchHost(t *testing.T) {
	cases := []struct {
		pat, host string
		want      bool
	}{
		{"github.com", "github.com", true},
		{"github.com", "api.github.com", false},
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "foo.bar.github.com", false},
		{"**.github.com", "api.github.com", true},
		{"**.github.com", "foo.bar.github.com", true},
		{"**.npmjs.org", "registry.npmjs.org", true},
		{"a.*.c", "a.b.c", true},
		{"a.*.c", "a.b.d.c", false},
		{"GITHUB.COM", "github.com", true},
	}
	for _, tc := range cases {
		got := policy.MatchHost(tc.pat, tc.host)
		if got != tc.want {
			t.Fatalf("MatchHost(%q,%q)=%v want %v", tc.pat, tc.host, got, tc.want)
		}
	}
}

func TestEvaluateHostPrecedence(t *testing.T) {
	d := policy.EvaluateHost(
		[]string{"**.example.com"},
		[]string{"evil.example.com"},
		"evil.example.com",
	)
	if d.Allow || d.Rule != "deniedHosts" {
		t.Fatalf("got %+v", d)
	}
	d = policy.EvaluateHost([]string{"github.com"}, nil, "gitlab.com")
	if d.Allow || d.Rule != "default" {
		t.Fatalf("got %+v", d)
	}
}

func TestValidatePattern(t *testing.T) {
	if err := policy.ValidatePattern("google.co*"); err == nil {
		t.Fatal("expected error for partial wildcard")
	}
	if err := policy.ValidatePattern("**.github.com"); err != nil {
		t.Fatal(err)
	}
}
