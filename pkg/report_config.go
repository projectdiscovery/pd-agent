package pkg

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	nucleiyaml "github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
)

// checkMessageReportingConfig refuses a reporting config that arrived in a
// work message when nuclei would read this host's environment or file system
// to apply it.
//
// The config is decoded with the same decoder nuclei uses, so YAML tags, merge
// keys and aliases resolve to the options nuclei would really apply. nuclei
// still validates the config itself when the engine starts.
//
// nuclei replaces any string option that starts with "$" with the environment
// variable of that name before it sends the config to a tracker, so a value
// such as "$PDCP_API_KEY" would ship the agent's own credentials to whatever
// tracker URL the config names. Operators who want environment references set
// PDCP_REPORTING_CONFIG, which is read from local disk and is not checked here.
func checkMessageReportingConfig(data []byte) error {
	opts := &reporting.Options{}
	if err := nucleiyaml.NewDecoder(bytes.NewReader(data)).Decode(opts); err != nil {
		return fmt.Errorf("parse reporting config: %w", err)
	}
	// The platform only sends trackers and remote exporters, so a work message
	// that names an exporter writing to this host did not come from it.
	fileExporters := []struct {
		name string
		set  bool
	}{
		{"markdown", opts.MarkdownExporter != nil},
		{"sarif", opts.SarifExporter != nil},
		{"json", opts.JSONExporter != nil},
		{"jsonl", opts.JSONLExporter != nil},
		{"pdf", opts.PDFExporter != nil},
	}
	for _, exporter := range fileExporters {
		if exporter.set {
			return fmt.Errorf("reporting config section %q writes to the agent host", exporter.name)
		}
	}
	return checkNoEnvReference(reflect.ValueOf(opts).Elem(), "")
}

// checkNoEnvReference returns an error for the first option nuclei would
// expand from the environment. It follows the same struct walk as nuclei, which
// expands only string fields of its option structs, so list items and the
// values of Jira custom-fields, where "$Severity" style placeholders are a
// supported feature, are left alone.
func checkNoEnvReference(value reflect.Value, path string) error {
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		fieldType := value.Type().Field(i)
		if !fieldType.IsExported() {
			continue
		}
		name := path + "." + fieldType.Name
		switch {
		case field.Kind() == reflect.Struct:
			if err := checkNoEnvReference(field, name); err != nil {
				return err
			}
		case field.Kind() == reflect.Pointer && field.Elem().Kind() == reflect.Struct:
			if err := checkNoEnvReference(field.Elem(), name); err != nil {
				return err
			}
		case field.Kind() == reflect.String:
			if _, ok := fieldType.Tag.Lookup("yaml"); ok && strings.HasPrefix(field.String(), "$") {
				return fmt.Errorf("reporting config value at %q references an environment variable", name)
			}
		}
	}
	return nil
}
