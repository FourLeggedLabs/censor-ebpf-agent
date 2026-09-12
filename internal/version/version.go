package version

// Version is injected at link time via -ldflags.
var Version = "dev"

func String() string {
	return Version
}
