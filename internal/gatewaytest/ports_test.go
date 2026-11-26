// Test port issue: a port returns to the pool when the test that took it
// ends, and test processes of one package draw from separate sub-blocks.

package gatewaytest

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// usePorts sets the port block of this process for one test and restores
// the previous block when it ends.
func usePorts(t *testing.T, first, last int) {
	issuedPorts.Lock()
	before, seen := [2]int{issuedPorts.first, issuedPorts.last}, issuedPorts.seen
	issuedPorts.first, issuedPorts.last, issuedPorts.seen = first, last, map[int]bool{}
	issuedPorts.Unlock()
	t.Cleanup(func() {
		issuedPorts.Lock()
		defer issuedPorts.Unlock()
		issuedPorts.first, issuedPorts.last, issuedPorts.seen = before[0], before[1], seen
	})
}

func TestFreeAddrReusesReleasedPorts(t *testing.T) {
	usePorts(t, 30000, 30009)
	for i := range 15 {
		t.Run(fmt.Sprintf("draw-%d", i), func(t *testing.T) {
			FreeAddr(t)
		})
	}
}

// childPorts names the block a child process of TestPortBlocksPerProcess
// claims from.
const childPorts = "GATEWAYTEST_CHILD_PORTS"

func TestPortBlocksPerProcess(t *testing.T) {
	const children = 4
	type child struct {
		cmd   *exec.Cmd
		stdin io.WriteCloser
		lines *bufio.Scanner
	}
	var started []child
	for range children {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPortBlockChild$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), childPorts+"=30100-30499")
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		started = append(started, child{cmd, stdin, bufio.NewScanner(stdout)})
	}
	var blocks [][2]int
	for i, c := range started {
		// Each child reports its block, then holds its ports until its input closes.
		var block [2]int
		held := false
		for c.lines.Scan() {
			line := c.lines.Text()
			if _, err := fmt.Sscanf(strings.TrimSpace(line), "block %d-%d", &block[0], &block[1]); err == nil {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), "holding") {
				held = true
				break
			}
			t.Logf("child %d: %s", i, line)
		}
		if !held {
			t.Errorf("child %d ended before holding its ports (block %v)", i, block)
		}
		blocks = append(blocks, block)
	}
	for _, c := range started {
		c.stdin.Close()
		c.cmd.Wait()
	}
	for i := range blocks {
		for j := i + 1; j < len(blocks); j++ {
			if blocks[i][0] <= blocks[j][1] && blocks[j][0] <= blocks[i][1] {
				t.Errorf("children %d and %d draw from overlapping blocks %v and %v", i, j, blocks[i], blocks[j])
			}
		}
	}
}

// TestPortBlockChild is the child process of TestPortBlocksPerProcess: it
// claims a block, binds ports drawn from it and holds them until its input
// closes.
func TestPortBlockChild(t *testing.T) {
	spec := os.Getenv(childPorts)
	if spec == "" {
		t.Skip("runs as a child of TestPortBlocksPerProcess")
	}
	var first, last int
	if _, err := fmt.Sscanf(spec, "%d-%d", &first, &last); err != nil {
		t.Fatal(err)
	}
	if err := claimPorts(first, last); err != nil {
		t.Fatal(err)
	}
	issuedPorts.Lock()
	fmt.Printf("block %d-%d\n", issuedPorts.first, issuedPorts.last)
	issuedPorts.Unlock()
	for range 20 {
		l, err := net.Listen("tcp", FreeAddr(t))
		if err != nil {
			t.Fatalf("bind: %v", err)
		}
		defer l.Close()
	}
	fmt.Println("holding")
	io.Copy(io.Discard, os.Stdin)
}
