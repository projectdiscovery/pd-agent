package tools

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/pdtm/pkg/types"
)

var (
	// retrieve home directory or fail
	HomeDir = func() string {
		home, err := os.UserHomeDir()
		if err != nil {
			gologger.Fatal().Msgf("Failed to get user home directory: %s", err)
		}
		return home
	}()

	DefaultConfigLocation = filepath.Join(HomeDir, ".config/pdtm/config.yaml")
	CacheFile             = filepath.Join(HomeDir, ".config/pdtm/cache.json")
	DefaultPath           = filepath.Join(HomeDir, ".pdtm/go/bin")
)

// UpdateCache creates/updates cache file
func UpdateCache(toolList []types.Tool) error {
	b, err := json.Marshal(toolList)
	if err != nil {
		return err
	}
	return os.WriteFile(CacheFile, b, os.ModePerm)
}

// FetchFromCache loads tool list from cache file
func FetchFromCache() ([]types.Tool, error) {
	b, err := os.ReadFile(CacheFile)
	if err != nil {
		return nil, err
	}
	var toolList []types.Tool
	if err := json.Unmarshal(b, &toolList); err != nil {
		return nil, err
	}
	return toolList, nil
}
