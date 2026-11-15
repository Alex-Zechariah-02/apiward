// A keys reload: the configuration file read again with the checks of a
// start, applied only when no setting changed that takes effect at a restart.

package gateway

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// reloadable are the settings a keys reload applies; every other setting
// takes effect only at a restart. The listener certificate is read again from
// the files named at start.
var reloadable = []string{"gateway.jwt", "upstream.allow_public_addresses", "upstream.tls_profiles", "upstream.tls_session_lifetime"}

// reloadKeys reads the configuration file again, as LoadSettings does, and
// returns its trust and upstream network settings. It refuses, naming them,
// any other setting the file now holds differently, since a reload would not
// apply it.
func (cfg nativeConfig) reloadKeys() (pipeline.TrustConfig, *forward.Network, error) {
	reloaded, err := loadChecked(cfg.source.path)
	if err != nil {
		return pipeline.TrustConfig{}, nil, err
	}
	changed, err := restartOnly(cfg.file, reloaded.file)
	if err != nil {
		return pipeline.TrustConfig{}, nil, err
	}
	if len(changed) > 0 {
		return pipeline.TrustConfig{}, nil, fmt.Errorf("changed settings take effect only at a restart: %s", strings.Join(changed, ", "))
	}
	return reloaded.controller.JWT, reloaded.controller.Network, nil
}

// restartOnly names the settings other than the reloadable ones that differ
// between two configurations, sorted.
func restartOnly(running, reloaded nativeFile) ([]string, error) {
	before, err := settingValues(running)
	if err != nil {
		return nil, err
	}
	after, err := settingValues(reloaded)
	if err != nil {
		return nil, err
	}
	var changed []string
	for name, value := range after {
		if !slices.Contains(reloadable, name) && before[name] != value {
			changed = append(changed, name)
		}
	}
	slices.Sort(changed)
	return changed, nil
}

// settingValues is each setting of f by its name ("data.listen") as JSON
// text; the version is a setting of its own.
func settingValues(f nativeFile) (map[string]string, error) {
	data, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(data, &sections); err != nil {
		return nil, err
	}
	values := map[string]string{}
	for section, raw := range sections {
		var members map[string]json.RawMessage
		if json.Unmarshal(raw, &members) != nil {
			values[section] = string(raw)
			continue
		}
		for name, value := range members {
			values[section+"."+name] = string(value)
		}
	}
	return values, nil
}
