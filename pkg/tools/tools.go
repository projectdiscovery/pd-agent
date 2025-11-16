package tools

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/pd-agent/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
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

	DefaultConfigLocation = filepath.Join(HomeDir, ".config/pd-agent/config.yaml")
	CacheFile             = filepath.Join(HomeDir, ".config/pd-agent/cache.json")
	DefaultPath           = filepath.Join(HomeDir, ".pd-agent/go/bin")
)

// UpdateCache creates/updates cache file
func UpdateCache(toolList []types.Tool) error {
	b, err := json.Marshal(toolList)
	if err != nil {
		return err
	}
	if fileutil.FolderExists(filepath.Dir(CacheFile)) {
		if err := os.MkdirAll(filepath.Dir(CacheFile), os.ModePerm); err != nil {
			return err
		}
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
