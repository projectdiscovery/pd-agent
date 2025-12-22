package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-github/v62/github"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/pd-agent/pkg/version"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
)

// BinaryUpdater handles self-updates of the pd-agent binary
type BinaryUpdater struct {
	repoOwner      string
	repoName       string
	currentVersion string
	checkInterval  time.Duration
	lastCheck      time.Time
}

// UpdateInfo contains information about an available update
type UpdateInfo struct {
	Version      string
	ReleaseURL   string
	AssetURL     string
	AssetName    string
	ReleaseNotes string
}

// NewBinaryUpdater creates a new binary updater
func NewBinaryUpdater(repoOwner, repoName string) *BinaryUpdater {
	currentVersion := strings.TrimPrefix(version.GetVersion(), "v")

	return &BinaryUpdater{
		repoOwner:      repoOwner,
		repoName:       repoName,
		currentVersion: currentVersion,
		checkInterval:  24 * time.Hour, // Check once per day
	}
}

// CheckForUpdate checks for available updates (only stable releases)
func (b *BinaryUpdater) CheckForUpdate(ctx context.Context) (*UpdateInfo, error) {
	gologger.Info().Msg("self-update: checking for available updates")
	gologger.Info().Msgf("self-update: current version is %s", b.currentVersion)

	// Use GitHub API to get latest stable (non-prerelease) release
	gologger.Info().Msgf("self-update: fetching releases from GitHub (%s/%s)", b.repoOwner, b.repoName)
	client := github.NewClient(nil)
	releases, _, err := client.Repositories.ListReleases(ctx, b.repoOwner, b.repoName, &github.ListOptions{
		PerPage: 10, // Check first 10 releases
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list releases: %w", err)
	}
	gologger.Info().Msgf("self-update: found %d releases", len(releases))

	if len(releases) == 0 {
		gologger.Info().Msg("self-update: no releases found")
		return nil, nil // No releases found
	}

	// Find first non-prerelease release
	gologger.Info().Msg("self-update: filtering for stable (non-prerelease) releases")
	var latestStable *github.RepositoryRelease
	for _, release := range releases {
		if release.Prerelease == nil || !*release.Prerelease {
			latestStable = release
			break
		}
	}

	if latestStable == nil {
		gologger.Info().Msg("self-update: no stable releases found")
		return nil, nil // No stable releases found
	}

	// Parse version from tag (remove 'v' prefix if present)
	tagName := latestStable.GetTagName()
	versionStr := strings.TrimPrefix(tagName, "v")
	gologger.Info().Msgf("self-update: latest stable release is %s", versionStr)

	// Filter out pre-releases by checking version string (additional check)
	if strings.Contains(versionStr, "-") {
		gologger.Info().Msgf("self-update: skipping pre-release version %s", versionStr)
		return nil, nil
	}

	// Parse current version
	gologger.Info().Msgf("self-update: comparing versions (current: %s, latest: %s)", b.currentVersion, versionStr)
	currentVer, err := semver.NewVersion(b.currentVersion)
	if err != nil {
		// If current version can't be parsed, assume it's a dev build and allow update
		gologger.Info().Msgf("self-update: current version '%s' is not a valid semver, allowing update", b.currentVersion)
	} else {
		// Compare versions - only update if newer
		latestVer, err := semver.NewVersion(versionStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse latest version: %w", err)
		}

		if !latestVer.GreaterThan(currentVer) {
			gologger.Info().Msgf("self-update: already running latest version (%s)", b.currentVersion)
			return nil, nil // No update available
		}
		gologger.Info().Msgf("self-update: update available (current: %s, latest: %s)", b.currentVersion, versionStr)
	}

	// Log available assets for debugging
	if len(latestStable.Assets) > 0 {
		gologger.Info().Msgf("self-update: release has %d assets:", len(latestStable.Assets))
		for _, asset := range latestStable.Assets {
			gologger.Info().Msgf("self-update:   - %s (%s)", asset.GetName(), asset.GetContentType())
		}
	} else {
		gologger.Warning().Msg("self-update: release has no assets")
		return nil, fmt.Errorf("release has no assets")
	}

	// Try to find asset manually using expected naming pattern
	// Pattern: pd-agent_{version}_{OS}_{ARCH}.zip (e.g., pd-agent_0.1.1_macOS_arm64.zip)
	osName := runtime.GOOS
	if osName == "darwin" {
		osName = "macOS"
	}
	arch := runtime.GOARCH
	expectedAssetName := fmt.Sprintf("pd-agent_%s_%s_%s.zip", versionStr, osName, arch)
	gologger.Info().Msgf("self-update: looking for asset matching pattern: %s", expectedAssetName)

	var matchingAsset *github.ReleaseAsset
	for _, asset := range latestStable.Assets {
		if asset.GetName() == expectedAssetName {
			matchingAsset = asset
			gologger.Info().Msgf("self-update: found matching asset: %s", asset.GetName())
			break
		}
	}

	if matchingAsset == nil {
		// Try alternative patterns
		altPatterns := []string{
			fmt.Sprintf("pd-agent_%s_%s_%s.zip", versionStr, runtime.GOOS, runtime.GOARCH),
			fmt.Sprintf("pd-agent_%s_%s_%s.tar.gz", versionStr, osName, arch),
			fmt.Sprintf("pd-agent_%s_%s_%s.tar.gz", versionStr, runtime.GOOS, runtime.GOARCH),
		}
		for _, pattern := range altPatterns {
			for _, asset := range latestStable.Assets {
				if asset.GetName() == pattern {
					matchingAsset = asset
					gologger.Info().Msgf("self-update: found matching asset with alternative pattern: %s", asset.GetName())
					break
				}
			}
			if matchingAsset != nil {
				break
			}
		}
	}

	if matchingAsset == nil {
		gologger.Error().Msgf("self-update: no matching asset found for platform %s/%s", runtime.GOOS, runtime.GOARCH)
		return nil, fmt.Errorf("no matching asset found for platform %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Use manually found asset instead of library's DetectVersion
	// The library expects different naming patterns, so we find the asset ourselves
	gologger.Info().Msgf("self-update: using manually found asset: %s", matchingAsset.GetName())

	return &UpdateInfo{
		Version:      versionStr,
		ReleaseURL:   latestStable.GetHTMLURL(),
		AssetURL:     matchingAsset.GetBrowserDownloadURL(),
		AssetName:    matchingAsset.GetName(),
		ReleaseNotes: latestStable.GetBody(),
	}, nil
}

// Update downloads and installs the latest version
func (b *BinaryUpdater) Update(ctx context.Context) error {
	// First check for update to get the version
	updateInfo, err := b.CheckForUpdate(ctx)
	if err != nil {
		return fmt.Errorf("failed to check for update: %w", err)
	}

	if updateInfo == nil {
		gologger.Info().Msg("self-update: already running latest version")
		return nil
	}

	gologger.Info().Msgf("self-update: update available (%s -> %s)", b.currentVersion, updateInfo.Version)
	gologger.Info().Msgf("self-update: downloading update from %s", updateInfo.ReleaseURL)

	// Get current executable path
	gologger.Info().Msg("self-update: getting current executable path")
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	gologger.Info().Msgf("self-update: executable path: %s", exe)

	// Create backup
	backupPath := exe + ".backup"
	gologger.Info().Msg("self-update: creating backup of current binary")
	if err := b.createBackup(exe, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	gologger.Info().Msgf("self-update: backup created at %s", backupPath)

	// Use library's UpdateTo with the asset URL we found manually
	// The library will handle download, extraction, and installation
	gologger.Info().Msgf("self-update: downloading and installing from asset URL: %s", updateInfo.AssetURL)
	gologger.Info().Msgf("self-update: asset name: %s", updateInfo.AssetName)

	if err := selfupdate.UpdateTo(updateInfo.AssetURL, exe); err != nil {
		gologger.Error().Msgf("self-update: failed to install update, restoring backup: %v", err)
		// Restore backup on failure
		if restoreErr := b.restoreBackup(backupPath, exe); restoreErr != nil {
			gologger.Error().Msgf("self-update: failed to restore backup: %v", restoreErr)
		} else {
			gologger.Info().Msg("self-update: backup restored successfully")
		}
		return fmt.Errorf("failed to update: %w", err)
	}

	gologger.Info().Msgf("self-update: successfully updated to version %s", updateInfo.Version)

	// Clean up backup after successful update
	gologger.Info().Msg("self-update: cleaning up backup file")
	_ = os.Remove(backupPath)

	return nil
}

// StartUpdateLoop starts the periodic update check loop
func (b *BinaryUpdater) StartUpdateLoop(ctx context.Context, updateCallback func() error) {
	ticker := time.NewTicker(b.checkInterval)
	defer ticker.Stop()

	// Initial check
	b.checkAndUpdate(ctx, updateCallback)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.checkAndUpdate(ctx, updateCallback)
		}
	}
}

// checkAndUpdate checks for updates and applies them if available
func (b *BinaryUpdater) checkAndUpdate(ctx context.Context, updateCallback func() error) {
	// Prevent multiple concurrent update checks
	now := time.Now()
	if now.Sub(b.lastCheck) < 1*time.Hour {
		gologger.Verbose().Msg("self-update: skipping check (already checked recently)")
		return // Already checked recently
	}
	b.lastCheck = now

	gologger.Info().Msg("self-update: starting update check")
	updateInfo, err := b.CheckForUpdate(ctx)
	if err != nil {
		gologger.Warning().Msgf("self-update: failed to check for updates: %v", err)
		return
	}

	if updateInfo == nil {
		gologger.Info().Msg("self-update: no update available")
		return
	}

	gologger.Info().Msgf("self-update: update available: version %s", updateInfo.Version)

	// Perform update
	gologger.Info().Msg("self-update: starting update process")
	if err := b.Update(ctx); err != nil {
		gologger.Error().Msgf("self-update: failed to update binary: %v", err)
		return
	}

	// Restart the application
	gologger.Info().Msg("self-update: restarting application with new binary")
	if err := b.restartApplication(); err != nil {
		gologger.Error().Msgf("self-update: failed to restart application: %v", err)
	}
}

// createBackup creates a backup of the current binary
func (b *BinaryUpdater) createBackup(src, dst string) error {
	gologger.Info().Msgf("self-update: creating backup at %s", dst)

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		_ = srcFile.Close()
	}()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		_ = dstFile.Close()
	}()

	_, err = dstFile.ReadFrom(srcFile)
	if err != nil {
		_ = os.Remove(dst)
		return err
	}

	// Make backup executable
	if err := os.Chmod(dst, 0755); err != nil {
		gologger.Warning().Msgf("Failed to set backup permissions: %v", err)
	}

	return nil
}

// restoreBackup restores the binary from backup
func (b *BinaryUpdater) restoreBackup(backup, target string) error {
	gologger.Info().Msgf("self-update: restoring from backup: %s", backup)

	backupFile, err := os.Open(backup)
	if err != nil {
		return err
	}
	defer func() {
		_ = backupFile.Close()
	}()

	targetFile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer func() {
		_ = targetFile.Close()
	}()

	_, err = targetFile.ReadFrom(backupFile)
	if err != nil {
		return err
	}

	// Make restored binary executable
	if err := os.Chmod(target, 0755); err != nil {
		gologger.Warning().Msgf("Failed to set restored binary permissions: %v", err)
	}

	return nil
}

// restartApplication restarts the current application
func (b *BinaryUpdater) restartApplication() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Get command-line arguments (excluding the executable path)
	args := os.Args[1:]

	// Start new process
	cmd := exec.Command(exe, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start new process: %w", err)
	}

	// Exit current process
	os.Exit(0)
	return nil
}
