package main

import (
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/pd-agent/pkg/runtools"
	"gopkg.in/yaml.v3"
)

// retestNeedsHeadless reports whether a retest template uses the headless
// protocol. Turning headless on makes nuclei find or download a browser before
// it runs anything, so a host without one could not retest even plain HTTP
// findings. An unreadable template keeps headless on, as before.
func retestNeedsHeadless(template []byte) bool {
	var top map[string]any
	if err := yaml.Unmarshal(template, &top); err != nil || top == nil {
		return true
	}
	_, ok := top["headless"]
	return ok
}

// retestHeadlessOption turns headless on with the installed browser when there
// is one, as scans do; otherwise nuclei falls back to downloading its own.
func retestHeadlessOption() nuclei.NucleiSDKOptions {
	_, installed := runtools.SystemChromePath()
	return nuclei.EnableHeadlessWithOpts(&nuclei.HeadlessOpts{UseChrome: installed})
}
