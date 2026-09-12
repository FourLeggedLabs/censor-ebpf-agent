package policy

import (
	"fmt"
	"strings"
)

// MatchHost reports whether host matches pattern.
// Semantics (CargoWall-compatible):
//   - exact label match (case-insensitive)
//   - * matches exactly one DNS label
//   - ** matches one or more DNS labels
// Wildcards must be full labels (not partial like google.co*).
func MatchHost(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if pattern == "" || host == "" {
		return false
	}
	return matchLabels(strings.Split(pattern, "."), strings.Split(host, "."))
}

func matchLabels(pat, host []string) bool {
	i, j := 0, 0
	for i < len(pat) && j < len(host) {
		switch pat[i] {
		case "**":
			// Consume remaining pattern after ** by trying successive host advances.
			if i == len(pat)-1 {
				return true
			}
			for k := j; k < len(host); k++ {
				if matchLabels(pat[i+1:], host[k:]) {
					return true
				}
			}
			return false
		case "*":
			i++
			j++
		default:
			if pat[i] != host[j] {
				return false
			}
			i++
			j++
		}
	}
	// Trailing ** can match empty remaining only if at least one label was required —
	// plan says ** matches one or more, so trailing ** with no host left is false
	// unless we already consumed via the i==len-1 branch above.
	for i < len(pat) && pat[i] == "**" && i == len(pat)-1 {
		// unmatched trailing ** needs ≥1 host label; none left → false
		return false
	}
	return i == len(pat) && j == len(host)
}

// Decision is the result of evaluating a host against policy lists.
type Decision struct {
	Allow bool
	Rule  string // which list matched, or "default"
}

// EvaluateHost applies deniedHosts over allowedHosts; unmatched is deny.
func EvaluateHost(allowed, denied []string, host string) Decision {
	for _, p := range denied {
		if MatchHost(p, host) {
			return Decision{Allow: false, Rule: "deniedHosts"}
		}
	}
	for _, p := range allowed {
		if MatchHost(p, host) {
			return Decision{Allow: true, Rule: "allowedHosts"}
		}
	}
	return Decision{Allow: false, Rule: "default"}
}

// ValidatePattern rejects empty patterns and partial-label wildcards.
func ValidatePattern(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return fmt.Errorf("empty host pattern")
	}
	for _, label := range strings.Split(strings.ToLower(p), ".") {
		if label == "*" || label == "**" {
			continue
		}
		if strings.ContainsAny(label, "*") {
			return fmt.Errorf("partial-label wildcard not allowed: %q", p)
		}
	}
	return nil
}
