// The TCP ports a process listens on, read with netstat on Windows.

package gatewaytest

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// ListeningPorts lists the TCP ports a process listens on, using netstat.
// The state column is in the display language, so a listening socket is
// told by its foreign port 0, which no connection has; output without any
// TCP row fails the test instead of reading as no listener.
func ListeningPorts(t *testing.T, pid int) []string {
	t.Helper()
	out, err := exec.Command("netstat", "-ano", "-p", "TCP").Output()
	if err != nil {
		t.Fatalf("netstat: %v", err)
	}
	rows := 0
	var ports []string
	for line := range strings.SplitSeq(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != "TCP" {
			continue
		}
		rows++
		if Port(fields[2]) == "0" && fields[4] == strconv.Itoa(pid) {
			ports = append(ports, Port(fields[1]))
		}
	}
	if rows == 0 {
		t.Fatalf("netstat output has no TCP row:\n%s", out)
	}
	return ports
}
