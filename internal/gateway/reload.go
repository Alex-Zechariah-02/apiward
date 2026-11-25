// A keys reload: the configuration file read again with the checks of a
// start; the reloadable settings are applied, and the settings that changed
// but take effect only at a restart are returned as warnings.

package gateway

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/Alex-Zechariah-02/apiward/internal/audit"
	"github.com/Alex-Zechariah-02/apiward/internal/forward"
	"github.com/Alex-Zechariah-02/apiward/internal/operator"
	"github.com/Alex-Zechariah-02/apiward/internal/pipeline"
)

// reloadable are the settings a keys reload applies; every other setting
// takes effect only at a restart. The listener certificate is read again from
// the files named at start.
var reloadable = []string{"gateway.jwt", "upstream.allow_public_addresses", "upstream.tls_profiles", "upstream.tls_session_lifetime", "upstream.identity_key", "upstream.retiring_identity_key"}

// reloadKeys reads the configuration file again, with the checks of a start,
// and returns its trust, upstream network and identity key settings. Every
// other setting the file now holds differently is named in the warnings: a
// reload does not apply it, and refusing the whole reload for it would keep
// a compromised key in force.
func (cfg nativeConfig) reloadKeys() (pipeline.TrustConfig, *forward.Network, *pipeline.Signer, []string, error) {
	reloaded, err := readNativeConfig(cfg.source.path)
	if err == nil {
		err = reloaded.loadNetwork()
	}
	if err == nil && !cfg.unsigned {
		err = reloaded.identity(reloaded.file.Upstream)
		if err == nil {
			err = reloaded.requireIdentity()
		}
	}
	if err == nil {
		err = operator.CheckPaths(reloaded.source.path, operatorConfig(reloaded), "run", nil)
	}
	if err != nil {
		return pipeline.TrustConfig{}, nil, nil, nil, err
	}
	changed, err := restartOnly(cfg.file, reloaded.file)
	if err != nil {
		return pipeline.TrustConfig{}, nil, nil, nil, err
	}
	cfg.reloaded.Store(&audit.Event{Kind: "gateway.reloaded", File: reloaded.source.path, Digest: reloaded.source.digest, ResolvedDigest: resolvedDigest(reloaded.file)})
	var warnings []string
	if len(changed) > 0 {
		warnings = []string{"changed settings take effect only at a restart: " + strings.Join(changed, ", ")}
	}
	var signer *pipeline.Signer
	if !cfg.unsigned {
		signer = reloaded.signer
	}
	return reloaded.controller.JWT, reloaded.controller.Network, signer, warnings, nil
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

// reloadedRecord is the gateway.reloaded record of the settings the last
// reload read; a reload that failed later records nothing (the controller
// calls this only once a reload is applied).
func (cfg nativeConfig) reloadedRecord() audit.Event {
	if e := cfg.reloaded.Load(); e != nil {
		return *e
	}
	return audit.Event{Kind: "gateway.reloaded"}
}
