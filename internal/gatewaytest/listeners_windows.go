// The TCP ports a process listens on, read with netstat on Windows.

package gatewaytest

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// ListeningPorts lists the TCP ports a process listens on, using netstat.
func ListeningPorts(t *testing.T, pid int) []string {
	t.Helper()
	out, err := exec.Command("netstat", "-ano", "-p", "TCP").Output()
	if err != nil {
		t.Fatalf("netstat: %v", err)
	}
	var ports []string
	for line := range strings.SplitSeq(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && fields[3] == "LISTENING" && fields[4] == strconv.Itoa(pid) {
			ports = append(ports, Port(fields[1]))
		}
	}
	return ports
}
