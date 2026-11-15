// The TCP ports a process listens on, read from the Windows listener table.
// netstat was used before: while thousands of connections open and close, it
// can print its header and no rows with exit status 0.

package gatewaytest

import (
	"encoding/binary"
	"strconv"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// listenerTable is the IPv4 listener class of GetExtendedTcpTable, each row
// with its owning process (TCP_TABLE_OWNER_PID_LISTENER in TCP_TABLE_CLASS).
const listenerTable = 3

var extendedTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

// tcpRow is MIB_TCPROW_OWNER_PID; the ports are in network byte order in
// the low 16 bits.
type tcpRow struct {
	state, localAddr, localPort, remoteAddr, remotePort, pid uint32
}

// ListeningPorts lists the IPv4 TCP ports a process listens on, the rows
// netstat -p TCP shows. A table without any listener fails the test instead
// of reading as no listener: the test's own receivers are always listening.
func ListeningPorts(t *testing.T, pid int) []string {
	t.Helper()
	rows := listeners(t)
	if len(rows) == 0 {
		t.Fatal("the listener table has no row")
	}
	var ports []string
	for _, row := range rows {
		if int(row.pid) == pid {
			port := row.localPort&0xff<<8 | row.localPort>>8&0xff
			ports = append(ports, strconv.FormatUint(uint64(port), 10))
		}
	}
	return ports
}

// listeners reads the listener table. The size the first call reports can
// be too small if a listener opens before the second call; the call then
// reports the new size, so it is asked again, at most three times.
func listeners(t *testing.T) []tcpRow {
	t.Helper()
	size := uint32(4096)
	for range 3 {
		buffer := make([]byte, size)
		code, _, _ := extendedTCPTable.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, listenerTable, 0)
		if windows.Errno(code) == windows.ERROR_INSUFFICIENT_BUFFER {
			continue
		}
		if code != 0 {
			t.Fatalf("GetExtendedTcpTable: %v", windows.Errno(code))
		}
		count := binary.LittleEndian.Uint32(buffer)
		return unsafe.Slice((*tcpRow)(unsafe.Pointer(&buffer[4])), count)
	}
	t.Fatal("GetExtendedTcpTable: the table kept growing")
	return nil
}
