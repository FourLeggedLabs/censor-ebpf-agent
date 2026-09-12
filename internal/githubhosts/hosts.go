package githubhosts

// DefaultHosts are destinations GitHub Actions runners need for the job to function.
var DefaultHosts = []string{
	"github.com",
	"api.github.com",
	"*.github.com",
	"**.githubusercontent.com",
	"**.githubassets.com",
	"ghcr.io",
	"**.docker.pkg.github.com",
	"objects.githubusercontent.com",
	"release-assets.githubusercontent.com",
	"codeload.github.com",
	"results-receiver.actions.githubusercontent.com",
	"pipelines.actions.githubusercontent.com",
}

// MergeAllowed prepends DefaultHosts when auto is true, de-duping exact strings.
func MergeAllowed(auto bool, allowed []string) []string {
	if !auto {
		return allowed
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(DefaultHosts)+len(allowed))
	for _, h := range append(append([]string{}, DefaultHosts...), allowed...) {
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}
