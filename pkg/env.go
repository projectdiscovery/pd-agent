package pkg

import envutil "github.com/projectdiscovery/utils/env"

var (
	PCDPApiServer = envutil.GetEnvOrDefault("PDCP_API_SERVER", "https://api.projectdiscovery.io")
)
