package pkg

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// fileExporterKeys are the nuclei reporting sections that write to a path on
// this host. The platform only sends trackers and remote exporters, so a work
// message that names one of these did not come from a reporting config.
var fileExporterKeys = []string{"markdown", "sarif", "json", "jsonl", "pdf"}

// checkMessageReportingConfig refuses a reporting config that arrived in a
// work message when nuclei would read this host's environment or file system
// to apply it.
//
// nuclei replaces any string value that starts with "$" with the environment
// variable of that name before it sends the config to a tracker, so a value
// such as "$PDCP_API_KEY" would ship the agent's own credentials to whatever
// tracker URL the config names. Operators who want environment references set
// PDCP_REPORTING_CONFIG, which is read from local disk and is not checked here.
func checkMessageReportingConfig(data []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse reporting config: %w", err)
	}
	if len(root.Content) == 0 {
		return nil
	}
	top := root.Content[0]
	if top.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(top.Content); i += 2 {
			key := top.Content[i].Value
			for _, denied := range fileExporterKeys {
				if key == denied {
					return fmt.Errorf("reporting config section %q writes to the agent host", key)
				}
			}
		}
	}
	return checkNoEnvReference(top, "")
}

// checkNoEnvReference returns an error for the first string that nuclei would
// expand from the environment. nuclei expands only string fields of its option
// structs, so list items and the values of Jira custom-fields, where "$Severity"
// style placeholders are a supported feature, are left alone.
func checkNoEnvReference(node *yaml.Node, path string) error {
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		node = node.Alias
	}
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag == "!!str" && strings.HasPrefix(node.Value, "$") {
			return fmt.Errorf("reporting config value at %q references an environment variable", path)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			if key == "custom-fields" {
				continue
			}
			if err := checkNoEnvReference(node.Content[i+1], path+"."+key); err != nil {
				return err
			}
		}
	}
	return nil
}
