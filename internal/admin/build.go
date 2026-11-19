// Build information: the module version, the Go toolchain and every
// compiled-in module, for the status reply and the version command.

package admin

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/Alex-Zechariah-02/apiward/module"
)

type buildModule struct {
	ID      string `json:"id"`
	Phase   string `json:"phase"`
	Version string `json:"version"`
}

type buildInfo struct {
	Version string        `json:"version"`
	Go      string        `json:"go"`
	Modules []buildModule `json:"modules"`
}

// currentBuild reads the build of the running binary; a binary built from a
// working tree reports the version "(devel)".
func currentBuild() buildInfo {
	b := buildInfo{Version: "(devel)", Go: runtime.Version(), Modules: []buildModule{}}
	if info, ok := debug.ReadBuildInfo(); ok {
		b.Go = info.GoVersion
		if info.Main.Version != "" {
			b.Version = info.Main.Version
		}
	}
	for _, m := range module.Registered() {
		b.Modules = append(b.Modules, buildModule{ID: m.ID, Phase: m.Phase.String(), Version: m.Version})
	}
	return b
}

// text is the version command's output: one fact per line.
func (b buildInfo) text() string {
	var out strings.Builder
	fmt.Fprintf(&out, "version %s\ngo %s\n", b.Version, b.Go)
	for _, m := range b.Modules {
		fmt.Fprintf(&out, "module %s %s %s\n", m.ID, m.Phase, m.Version)
	}
	return out.String()
}

// runningBuild is read once: the build cannot change while the process
// runs, and the status reply polled every second would otherwise read it each
// time. Readers must not change it.
var runningBuild = sync.OnceValue(currentBuild)

// VersionText is the version command's output for the running binary.
func VersionText() string { return runningBuild().text() }
