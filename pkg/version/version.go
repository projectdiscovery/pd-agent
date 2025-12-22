package version

// Version information set at build time via ldflags
var (
	// Version is the semantic version of the build
	Version = "v0.1.2"
)

// GetVersion returns the version string
func GetVersion() string {
	return Version
}
