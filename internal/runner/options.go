package runner

import (
	"os"

	"github.com/logrusorgru/aurora/v4"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/pdtm-agent/pkg/tools"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	envutil "github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	updateutils "github.com/projectdiscovery/utils/update"
	"github.com/rs/xid"
)

var au *aurora.Aurora

var (
	PDCPApiKey        = envutil.GetEnvOrDefault("PDCP_API_KEY", "")
	TeamIDEnv         = envutil.GetEnvOrDefault("PDCP_TEAM_ID", "")
	PunchHoleHost     = envutil.GetEnvOrDefault("PUNCH_HOLE_HOST", "proxy-dev.projectdiscovery.io")
	PunchHoleHTTPPort = envutil.GetEnvOrDefault("PUNCH_HOLE_HTTP_PORT", "8880")
)

// Options contains the configuration options for tuning the enumeration process.
type Options struct {
	ConfigFile string
	Path       string
	NoColor    bool
	SetPath    bool
	SetGoPath  bool
	UnSetPath  bool

	Install goflags.StringSlice
	Update  goflags.StringSlice
	Remove  goflags.StringSlice

	InstallAll bool
	UpdateAll  bool
	RemoveAll  bool

	Verbose            bool
	Silent             bool
	Version            bool
	ShowPath           bool
	DisableUpdateCheck bool
	DisableChangeLog   bool

	PdcpAuth         string
	PdcpAuthCredFile string
	TeamID           string

	AgentMode   bool
	AgentId     string
	AgentTags   goflags.StringSlice
	AgentOutput string
	AgentName   string

	MCPMode          bool
	PassiveDiscovery bool // Enable passive discovery
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()

	flagSet.SetDescription(`pdtm is a simple and easy-to-use golang based tool for managing open source projects from ProjectDiscovery`)

	flagSet.CreateGroup("config", "Config",
		flagSet.StringVar(&options.ConfigFile, "config", tools.DefaultConfigLocation, "cli flag configuration file"),
		flagSet.StringVarP(&options.Path, "binary-path", "bp", tools.DefaultPath, "custom location to download project binary"),
	)

	flagSet.CreateGroup("install", "Install",
		flagSet.StringSliceVarP(&options.Install, "install", "i", nil, "install single or multiple project by name (comma separated)", goflags.NormalizedStringSliceOptions),
		flagSet.BoolVarP(&options.InstallAll, "install-all", "ia", false, "install all the projects"),
		flagSet.BoolVarP(&options.SetPath, "install-path", "ip", false, "append path to PATH environment variables"),
		flagSet.BoolVarP(&options.SetGoPath, "install-go-path", "igp", false, "append GOBIN/GOPATH to PATH environment variables"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.StringSliceVarP(&options.Update, "update", "u", nil, "update single or multiple project by name (comma separated)", goflags.NormalizedStringSliceOptions),
		flagSet.BoolVarP(&options.UpdateAll, "update-all", "ua", false, "update all the projects"),
		flagSet.CallbackVarP(GetUpdateCallback(), "self-update", "up", "update pdtm to latest version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic pdtm update check"),
	)

	flagSet.CreateGroup("remove", "Remove",
		flagSet.StringSliceVarP(&options.Remove, "remove", "r", nil, "remove single or multiple project by name (comma separated)", goflags.NormalizedStringSliceOptions),
		flagSet.BoolVarP(&options.RemoveAll, "remove-all", "ra", false, "remove all the projects"),
		flagSet.BoolVarP(&options.UnSetPath, "remove-path", "rp", false, "remove path from PATH environment variables"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&options.ShowPath, "show-path", "sp", false, "show the current binary path then exit"),
		flagSet.BoolVar(&options.Version, "version", false, "show version of the project"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "show verbose output"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable output content coloring (ANSI escape codes)"),
		flagSet.BoolVarP(&options.DisableChangeLog, "dc", "disable-changelog", false, "disable release changelog in output"),
	)

	flagSet.CreateGroup("cloud", "Cloud",
		flagSet.DynamicVar(&options.PdcpAuth, "auth", "true", "configure projectdiscovery cloud (pdcp) api key"),
		flagSet.StringVarP(&options.PdcpAuthCredFile, "auth-config", "ac", "", "configure projectdiscovery cloud (pdcp) api key credential file"),
		flagSet.StringVarP(&options.TeamID, "team-id", "tid", TeamIDEnv, "upload asset results to given team id (optional)"),
		flagSet.BoolVar(&options.AgentMode, "agent", false, "agent mode"),
		flagSet.StringVar(&options.AgentOutput, "agent-output", "", "agent output folder"),
		flagSet.StringVar(&options.AgentId, "agent-id", "", "specify the id for the agent"),
		flagSet.StringSliceVarP(&options.AgentTags, "agent-tags", "at", nil, "specify the tags for the agent", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVar(&options.MCPMode, "mcp", false, "mcp mode"),
		flagSet.BoolVar(&options.PassiveDiscovery, "passive-discovery", false, "enable passive discovery via libpcap/gopacket"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	// configure aurora for logging
	au = aurora.New(aurora.WithColors(true))

	options.configureOutput()

	showBanner()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", version)
		os.Exit(0)
	}

	if options.ShowPath {
		// prints default path if not modified
		gologger.Silent().Msg(options.Path)
		os.Exit(0)
	}

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("pdtm", version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("pdtm version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current pdtm version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	if options.ConfigFile != tools.DefaultConfigLocation {
		_ = options.loadConfigFrom(options.ConfigFile)
	}

	// api key hierarchy: cli flag > env var > .pdcp/credential file
	// use dev api
	pdcpauth.DefaultApiServer = "https://api.dev.projectdiscovery.io"
	pdcpauth.DashBoardURL = "https://cloud-dev.projectdiscovery.io"

	h := &pdcpauth.PDCPCredHandler{}
	creds, err := h.GetCreds()
	if err != nil {
		if err != pdcpauth.ErrNoCreds {
			gologger.Verbose().Msgf("Could not get credentials for cloud upload: %s\n", err)
		}
		pdcpauth.CheckNValidateCredentials("pdtm")
		return nil
	}
	if apikey := os.Getenv("PDCP_API_KEY"); apikey != "" {
		PDCPApiKey = apikey
	} else {
		PDCPApiKey = creds.APIKey
	}

	if options.AgentId == "" {
		options.AgentId = xid.New().String()
	}

	// Also support env variable PASSIVE_DISCOVERY
	if os.Getenv("PASSIVE_DISCOVERY") == "1" || os.Getenv("PASSIVE_DISCOVERY") == "true" {
		options.PassiveDiscovery = true
	}

	return options
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
		au = aurora.New(aurora.WithColors(false))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

func (options *Options) loadConfigFrom(location string) error {
	return fileutil.Unmarshal(fileutil.YAML, []byte(location), options)
}
