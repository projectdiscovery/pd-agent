package selfupdate

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// childModeEnv makes the test binary act as the "new binary" Prevalidate starts.
const childModeEnv = "SELFUPDATE_TEST_CHILD"

func TestMain(m *testing.M) {
	switch os.Getenv(childModeEnv) {
	case "":
		os.Exit(m.Run())
	case "honors":
		// Current builds: print the marker, then hold past the old 15s window.
		if os.Getenv(PreflightEnvVar) == "1" {
			fmt.Println(PreflightOK)
			time.Sleep(time.Minute)
		}
		os.Exit(0)
	case "old-build":
		// Builds that ignore PDCP_PREFLIGHT start a full agent and keep running.
		time.Sleep(time.Minute)
		os.Exit(0)
	case "exits-clean":
		os.Exit(0)
	case "crashes":
		fmt.Fprintln(os.Stderr, "flag provided but not defined: -new-flag")
		os.Exit(2)
	}
	os.Exit(3)
}

func runPrevalidate(t *testing.T, mode string) error {
	t.Setenv(childModeEnv, mode)
	self, err := os.Executable()
	require.NoError(t, err)
	return Prevalidate(self, "agent-1")
}

func TestPrevalidateAcceptsBinaryThatHonorsPreflight(t *testing.T) {
	start := time.Now()
	require.NoError(t, runPrevalidate(t, "honors"))
	require.Less(t, time.Since(start), 10*time.Second, "must pass on the marker, not wait out the hold")
}

func TestPrevalidateRejectsBinaryThatKeepsRunningWithoutMarker(t *testing.T) {
	old := preflightWindow
	preflightWindow = 2 * time.Second
	t.Cleanup(func() { preflightWindow = old })

	err := runPrevalidate(t, "old-build")
	require.Error(t, err)
	require.Contains(t, err.Error(), "did not print")
}

func TestPrevalidateRejectsCleanExitWithoutMarker(t *testing.T) {
	err := runPrevalidate(t, "exits-clean")
	require.Error(t, err)
	require.Contains(t, err.Error(), "without printing")
}

func TestPrevalidateRejectsCrash(t *testing.T) {
	err := runPrevalidate(t, "crashes")
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "-new-flag"), err.Error())
}
