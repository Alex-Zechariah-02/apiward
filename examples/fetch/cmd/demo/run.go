// Demo run: starts the Fetch services and the gateway, waits until they listen
// and the gateway reports its admission, and stops every child it started.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// run starts the five Fetch services and the gateway, reports when all of them
// accept connections, and stops them all on interrupt, when the gateway
// exits, or with -stdin when standard input closes. A service that stops is
// reported and left stopped, so the gateway's answer for an unavailable API
// can be shown. Process output goes to log files in the demonstration
// directory.
func run(args []string) (runErr error) {
	set := flag.NewFlagSet("run", flag.ContinueOnError)
	gateway := set.String("gateway", "", "gateway binary")
	serviceBinary := set.String("services", "", "Fetch services binary")
	accountsBinary := set.String("accounts", "", "Fetch Accounts binary")
	stdin := set.Bool("stdin", false, "also stop when standard input closes")
	dir, err := parse(set, args)
	if err != nil {
		return err
	}
	if *gateway == "" || *serviceBinary == "" || *accountsBinary == "" {
		return errors.New("-gateway, -services and -accounts are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *stdin {
		go func() {
			io.Copy(io.Discard, os.Stdin)
			stop()
		}()
	}
	return runDemo(ctx, dir, *gateway, *serviceBinary, *accountsBinary, nil)
}

// runDemo is run's work: it stops everything when ctx ends. ready, if not
// nil, is called once every process listens and the gateway has reported
// its admission status.
func runDemo(ctx context.Context, dir, gateway, serviceBinary, accountsBinary string, ready func()) (runErr error) {
	if err := checkDemo(dir); err != nil {
		return err
	}
	if err := checkPortsFree(); err != nil {
		return err
	}

	// Each started process reports its exit on exited; running counts those
	// not yet received, so the cleanup waits for exactly the rest.
	type processExit struct {
		name string
		err  error
	}
	exited := make(chan processExit, len(fetchServices)+1)
	var processes []*exec.Cmd
	var gatewayLogStart int64
	running := 0
	defer func() {
		for _, process := range processes {
			// A process that already exited cannot be signalled. Its exit is
			// still received below, so every child is reaped exactly once.
			if err := interruptProcess(process); err != nil && !errors.Is(err, os.ErrProcessDone) {
				process.Process.Kill()
			}
		}
		timer := time.NewTimer(12 * time.Second)
		defer timer.Stop()
		for running > 0 {
			select {
			case result := <-exited:
				running--
				if result.err != nil {
					runErr = errors.Join(runErr, fmt.Errorf("%s stopped: %w; see its log in %s", result.name, result.err, dir))
				}
			case <-timer.C:
				for _, process := range processes {
					process.Process.Kill()
				}
				runErr = errors.Join(runErr, errors.New("child shutdown exceeded 12s; remaining processes killed"))
			}
		}
	}()
	start := func(name string, binary string, args ...string) error {
		logFile, err := os.OpenFile(filepath.Join(dir, name+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if name == "gateway" {
			info, err := logFile.Stat()
			if err != nil {
				logFile.Close()
				return err
			}
			gatewayLogStart = info.Size()
		}
		cmd := exec.Command(binary, args...)
		newProcessGroup(cmd)
		cmd.Stdout, cmd.Stderr = logFile, logFile
		if err := cmd.Start(); err != nil {
			logFile.Close()
			return fmt.Errorf("starting %s: %w", name, err)
		}
		processes = append(processes, cmd)
		running++
		go func() {
			err := cmd.Wait()
			logFile.Close()
			exited <- processExit{name: name, err: err}
		}()
		return nil
	}

	secret := filepath.Join(dir, secretFile)
	var addresses []string
	for _, f := range fetchServices {
		binary := serviceBinary
		args := []string{"-listen", f.listen, "-control", f.control, "-secret-file", secret}
		switch f.name {
		case "accounts":
			binary = accountsBinary
			args = append(args, "-signing-settings", filepath.Join(dir, signingFile))
		case "orders":
			args = append(args, "-service", f.name, "-inventory", "http://"+fetchServices[0].listen)
		case "reports":
			args = append(args, "-service", f.name, "-orders", "http://"+fetchServices[1].listen)
		default:
			args = append(args, "-service", f.name)
		}
		if err := start(f.name, binary, args...); err != nil {
			return err
		}
		addresses = append(addresses, f.listen, f.control)
	}
	if err := start("gateway", gateway, "run", "--config", filepath.Join(dir, configFile)); err != nil {
		return err
	}
	addresses = append(addresses, adminListen, dataListen, metricsListen)

	deadline := time.Now().Add(30 * time.Second)
	for _, address := range addresses {
		for !dialable(address) {
			select {
			case result := <-exited:
				running--
				return fmt.Errorf("%s exited during startup (%v); see %s", result.name, result.err, filepath.Join(dir, result.name+".log"))
			case <-ctx.Done():
				return nil
			case <-time.After(50 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s did not start listening; see the logs in %s", address, dir)
			}
		}
	}
	admission := ""
	for admission == "" {
		var err error
		admission, err = readAdmission(filepath.Join(dir, "gateway.log"), gatewayLogStart)
		if err != nil {
			return err
		}
		if admission != "" {
			break
		}
		select {
		case result := <-exited:
			running--
			return fmt.Errorf("%s exited before admission status (%v); see its log in %s", result.name, result.err, dir)
		case <-ctx.Done():
			return nil
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return errors.New("gateway did not report native admission status; see gateway.log")
		}
	}
	fmt.Printf("listening; protected admission: %s\n", admission)
	fmt.Printf("  dashboard: http://%s/\n  website:   http://%s/\n", adminListen, dataListen)
	for i, p := range processes {
		name := "gateway"
		if i < len(fetchServices) {
			name = fetchServices[i].name
		}
		fmt.Printf("  %-9s process %d\n", name, p.Process.Pid)
	}
	if ready != nil {
		ready()
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Println("stopping")
			return nil
		case result := <-exited:
			running--
			if result.name == "gateway" {
				return fmt.Errorf("the gateway exited (%v); see %s", result.err, filepath.Join(dir, "gateway.log"))
			}
			fmt.Printf("service %s stopped (%v); its gateway requests can now fail\n", result.name, result.err)
		}
	}
}

// checkPortsFree refuses a second demonstration on the same addresses.
func checkPortsFree() error {
	addresses := []string{adminListen, dataListen, metricsListen}
	for _, service := range fetchServices {
		addresses = append(addresses, service.listen, service.control)
	}
	for _, address := range addresses {
		if dialable(address) {
			return fmt.Errorf("%s is already in use; refusing to start a second demonstration", address)
		}
	}
	return nil
}

func dialable(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
