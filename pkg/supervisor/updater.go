package supervisor

import (
	"context"
	"fmt"
	"time"

	"github.com/projectdiscovery/gologger"
)

// Updater handles deployment image updates
type Updater struct {
	provider      Provider
	image         string
	checkInterval time.Duration
	lastCheck     time.Time
	lastImageID   string // Track last known image ID to detect changes
}

// NewUpdater creates a new updater
func NewUpdater(provider Provider, image string, checkInterval time.Duration) *Updater {
	return &Updater{
		provider:      provider,
		image:         image,
		checkInterval: checkInterval,
	}
}

// CheckForUpdates checks if a new image version is available
func (u *Updater) CheckForUpdates(ctx context.Context) (bool, error) {
	u.lastCheck = time.Now()

	// Get current image ID before pulling
	currentImageID, err := u.provider.GetImageID(ctx, u.image)
	if err != nil {
		// Image doesn't exist locally, we need to pull it
		return true, nil
	}

	// Store current image ID for comparison
	oldImageID := u.lastImageID
	u.lastImageID = currentImageID

	// If this is the first check, we don't know if there's an update
	// But we should still pull to ensure we have the latest
	if oldImageID == "" {
		return true, nil
	}

	// Compare with last known image ID
	// If they're the same, no update needed
	if currentImageID == oldImageID {
		return false, nil
	}

	// Image ID changed, update available
	return true, nil
}

// Update pulls the latest image and returns whether the image was actually updated
func (u *Updater) Update(ctx context.Context) (bool, error) {
	// Get image ID before pulling
	oldImageID, err := u.provider.GetImageID(ctx, u.image)
	if err != nil {
		// Image doesn't exist, we need to pull it
		oldImageID = ""
	}

	// If we have a last known image ID and it matches, skip the pull
	if u.lastImageID != "" && oldImageID != "" && u.lastImageID == oldImageID {
		// Image hasn't changed since last check, no need to pull
		return false, nil
	}

	gologger.Info().Msgf("Checking for updates for image: %s", u.image)

	// Pull the latest image
	if err := u.provider.PullImage(ctx, u.image); err != nil {
		return false, fmt.Errorf("failed to pull image: %w", err)
	}

	// Get image ID after pulling
	newImageID, err := u.provider.GetImageID(ctx, u.image)
	if err != nil {
		return false, fmt.Errorf("failed to get image ID after pull: %w", err)
	}

	// Check if image actually changed
	wasUpdated := false
	if oldImageID != "" && oldImageID != newImageID {
		wasUpdated = true
		gologger.Info().Msgf("Image updated: %s (old: %s, new: %s)", u.image, oldImageID[:12], newImageID[:12])
	} else if oldImageID == "" {
		// First time pulling
		gologger.Info().Msgf("Successfully pulled image: %s (ID: %s)", u.image, newImageID[:12])
	} else {
		// Image is up to date
		gologger.Verbose().Msgf("Image %s is already up to date (ID: %s)", u.image, newImageID[:12])
	}

	// Update last known image ID
	u.lastImageID = newImageID

	return wasUpdated, nil
}

// StartUpdateLoop starts the periodic update check loop
func (u *Updater) StartUpdateLoop(ctx context.Context, updateCallback func() error) {
	// Initial check - always pull on startup to ensure we have the latest
	// This happens once, not on a timer
	wasUpdated, err := u.Update(ctx)
	if err != nil {
		gologger.Warning().Msgf("Failed to update on startup: %v", err)
	} else if wasUpdated && updateCallback != nil {
		// Only restart if image was actually updated
		if err := updateCallback(); err != nil {
			gologger.Warning().Msgf("Update callback failed: %v", err)
		}
	}

	// Now start the periodic check loop (24 hours)
	ticker := time.NewTicker(u.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wasUpdated, err := u.Update(ctx)
			if err != nil {
				gologger.Warning().Msgf("Failed to update: %v", err)
				continue
			}

			// Only trigger restart if image was actually updated
			if wasUpdated && updateCallback != nil {
				if err := updateCallback(); err != nil {
					gologger.Warning().Msgf("Update callback failed: %v", err)
				}
			}
		}
	}
}

// GetLastCheck returns the last update check time
func (u *Updater) GetLastCheck() time.Time {
	return u.lastCheck
}
