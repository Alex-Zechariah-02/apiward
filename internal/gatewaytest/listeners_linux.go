// The TCP ports a process listens on, read with ss on Linux.

package gatewaytest

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// ListeningPorts lists the TCP ports a process listens on, using ss from
// iproute2; a socket can show several owners, so the pid is matched exactly.
func ListeningPorts(t *testing.T, pid int) []string {
	t.Helper()
	out, err := exec.Command("ss", "-H", "-l", "-t", "-n", "-p").Output()
	if err != nil {
		t.Fatalf("ss: %v", err)
	}
	owner := "pid=" + strconv.Itoa(pid) + ","
	var ports []string
	for line := range strings.SplitSeq(string(out), "\n") {
		fields := strings.Fields(line)
		// ss -H prints six fields: state, two queues, local and peer addresses, then the owner.
		if len(fields) >= 6 && fields[0] == "LISTEN" && strings.Contains(fields[5], owner) {
			ports = append(ports, Port(fields[3]))
		}
	}
	return ports
}
