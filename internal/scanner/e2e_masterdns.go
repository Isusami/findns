package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// MasterDnsOpts configures a MasterDnsVPN e2e probe.
//
// MasterDnsVPN's client takes its configuration from a TOML file (the only
// CLI flags are -config, -log, -version). For per-IP probing we render a
// minimal TOML per worker into a temp directory, set the subprocess working
// directory to that temp dir so the binary finds the per-call
// client_resolvers.txt, then drive the local SOCKS5 listener with the same
// CONNECT-based verifier used by DnsttCheckBin.
type MasterDnsOpts struct {
	// Domains is the tunnel domain(s); maps to TOML DOMAINS = [...].
	// At least one is required. The MasterDnsVPN client may try multiple
	// in order; the first that establishes wins.
	Domains []string

	// Key is the shared encryption key (matches server's encrypt_key.txt).
	// Written into TOML as ENCRYPTION_KEY = "...".
	Key string

	// EncryptionMethod selects the AEAD/cipher (0..5):
	//   0 = None, 1 = XOR, 2 = ChaCha20,
	//   3 = AES-128-GCM, 4 = AES-192-GCM, 5 = AES-256-GCM.
	// Must match the server. Out-of-range values are treated as 1 (XOR)
	// which mirrors the upstream code's normalisation behaviour.
	EncryptionMethod int

	// ConfigTemplate is an optional path to a base client_config.toml.
	// When set, that file's contents are used as the base and only the
	// "must-be-correct" keys (DOMAINS, ENCRYPTION_KEY, DATA_ENCRYPTION_METHOD,
	// LISTEN_IP, LISTEN_PORT, plus the single-shot safety knobs) are
	// overridden. Comments and unknown keys are preserved.
	// When empty, a minimal config is synthesised from sane defaults.
	ConfigTemplate string

	// MTUBisect, when true, asks the MasterDnsVPN client to write its
	// per-resolver MTU result file and parses it after the SOCKS5 probe
	// succeeds, attaching mdvpn_up_mtu / mdvpn_down_mtu metrics.
	// Costs an extra spawn cycle per resolver.
	MTUBisect bool
}

// MasterDnsCheckBin returns a CheckFunc that probes a resolver by spawning
// the masterdnsvpn-client binary, waiting for the local SOCKS5 listener to
// open, and driving a real SOCKS5 CONNECT through the tunnel.
//
// Mirrors DnsttCheckBin's process lifecycle (see e2e.go): port pool, temp
// workspace, kill+grace+drain on exit, single-failure diagnostic capture.
func MasterDnsCheckBin(bin string, opts MasterDnsOpts, ports chan int) CheckFunc {
	var diagOnce atomic.Bool

	return func(ip string, timeout time.Duration) (bool, Metrics) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		var port int
		select {
		case port = <-ports:
		case <-ctx.Done():
			return false, nil
		}
		// Always return the port to the pool when we leave this function.
		// Use a deferred closure so the value at call time is captured even
		// if we re-bind 'port' later (we don't, but defensive).
		defer func() {
			ports <- port
		}()

		// Per-call temp workspace for config + resolver list + (optional)
		// MTU result log. Cleaned up on return regardless of outcome.
		workDir, err := os.MkdirTemp("", "findns-mdvpn-")
		if err != nil {
			if diagOnce.CompareAndSwap(false, true) {
				setDiag("e2e/masterdns: cannot create temp dir: %v", err)
			}
			return false, nil
		}
		defer os.RemoveAll(workDir)

		mtuLogName := "mtu_results.log"
		cfg, err := RenderMasterDnsConfig(opts, ip, port, mtuLogName)
		if err != nil {
			if diagOnce.CompareAndSwap(false, true) {
				setDiag("e2e/masterdns: cannot render config: %v", err)
			}
			return false, nil
		}
		cfgPath := filepath.Join(workDir, "client_config.toml")
		if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
			if diagOnce.CompareAndSwap(false, true) {
				setDiag("e2e/masterdns: cannot write config: %v", err)
			}
			return false, nil
		}
		// MasterDnsVPN client looks for client_resolvers.txt next to its
		// CWD. We pin a single resolver per probe so balancing/health logic
		// can't pick a different one.
		resolverList := ip + "\n"
		if err := os.WriteFile(filepath.Join(workDir, "client_resolvers.txt"), []byte(resolverList), 0o600); err != nil {
			if diagOnce.CompareAndSwap(false, true) {
				setDiag("e2e/masterdns: cannot write resolver list: %v", err)
			}
			return false, nil
		}

		start := time.Now()

		var stderrBuf bytes.Buffer
		cmd := execCommandContext(ctx, bin, "-config", "client_config.toml")
		cmd.Dir = workDir
		cmd.Stdout = io.Discard
		cmd.Stderr = &boundedWriter{w: &stderrBuf, max: 8192}

		if err := cmd.Start(); err != nil {
			if diagOnce.CompareAndSwap(false, true) {
				setDiag("e2e/masterdns: cannot start %s: %v", bin, err)
			}
			return false, nil
		}

		exited := make(chan struct{})
		go func() {
			cmd.Wait()
			close(exited)
		}()

		// Always tear down the subprocess before this function returns so
		// the listen port is freed for the next worker.
		defer func() {
			cmd.Process.Kill()
			select {
			case <-exited:
			case <-time.After(2 * time.Second):
			}
			// Same 300ms drain pause as the dnstt path: gives the kernel
			// time to fully release the SOCKS5 listen port.
			time.Sleep(300 * time.Millisecond)
		}()

		if !waitAndTestSOCKS5Connect(ctx, port, exited) {
			if diagOnce.CompareAndSwap(false, true) {
				processExitedEarly := false
				select {
				case <-exited:
					processExitedEarly = true
				default:
				}
				cmd.Process.Kill()
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
				}
				stderr := strings.TrimSpace(stderrBuf.String())
				if stderr != "" {
					setDiag("e2e/masterdns first failure (ip=%s): masterdnsvpn-client stderr: %s", ip, truncate(stderr, 300))
				} else if processExitedEarly {
					setDiag("e2e/masterdns first failure (ip=%s): masterdnsvpn-client exited early with no stderr", ip)
				} else {
					setDiag("e2e/masterdns first failure (ip=%s): SOCKS5 handshake through tunnel timed out within %v", ip, timeout)
				}
			}
			return false, nil
		}

		ms := roundMs(float64(time.Since(start).Microseconds()) / 1000.0)
		metrics := Metrics{"mdvpn_e2e_ms": ms}

		if opts.MTUBisect {
			// Best-effort: if the upstream client wrote its MTU summary
			// while we were probing, parse it and attach the values.
			// Failure to parse is non-fatal — the resolver still passes.
			if up, down, ok := readMasterDnsMTU(filepath.Join(workDir, mtuLogName), ip); ok {
				metrics["mdvpn_up_mtu"] = up
				metrics["mdvpn_down_mtu"] = down
			}
		}

		return true, metrics
	}
}

// boundedWriter caps how much child-process stderr we keep in memory so a
// chatty client can't OOM a worker pool with a few thousand resolvers.
type boundedWriter struct {
	w   *bytes.Buffer
	max int
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	remaining := b.max - b.w.Len()
	if remaining <= 0 {
		// Pretend we consumed it so the child's pipe doesn't block.
		return len(p), nil
	}
	if len(p) > remaining {
		b.w.Write(p[:remaining])
		return len(p), nil
	}
	return b.w.Write(p)
}

// readMasterDnsMTU parses the MTU result file produced by MasterDnsVPN's
// built-in MTU tester when SAVE_MTU_SERVERS_TO_FILE = true. We format the
// output ourselves (see masterdns_config.go) so the parser stays simple and
// independent of the upstream binary's default format.
//
// Expected line: "<ip> UP=<int> DOWN=<int>"
//
// Returns 0,0,false if the file is absent, empty, malformed, or doesn't
// contain a row for this resolver. This is intentionally tolerant.
func readMasterDnsMTU(path, ip string) (up, down float64, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, ip) {
			continue
		}
		// "<ip> UP=<n> DOWN=<n>"
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		var u, d float64
		var seenU, seenD bool
		for _, f := range fields[1:] {
			switch {
			case strings.HasPrefix(f, "UP="):
				if v, err := strconv.ParseFloat(strings.TrimPrefix(f, "UP="), 64); err == nil {
					u, seenU = v, true
				}
			case strings.HasPrefix(f, "DOWN="):
				if v, err := strconv.ParseFloat(strings.TrimPrefix(f, "DOWN="), 64); err == nil {
					d, seenD = v, true
				}
			}
		}
		if seenU && seenD {
			return u, d, true
		}
	}
	return 0, 0, false
}

// LoadMasterDnsKey resolves the user-provided key options into a single
// secret string. File takes precedence over the inline flag (per the
// architectural decision recorded in the plan).
//
// Returns ("", nil) when neither is set, leaving the caller free to error
// or to default. Passing both is allowed: the file wins, no warning.
func LoadMasterDnsKey(inlineKey, keyFile string) (string, error) {
	if keyFile != "" {
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			return "", fmt.Errorf("reading masterdns key file %q: %w", keyFile, err)
		}
		// MasterDnsVPN treats the key as opaque bytes; trim only the
		// trailing newline that text editors add.
		k := strings.TrimRight(string(raw), "\r\n")
		if k == "" {
			return "", fmt.Errorf("masterdns key file %q is empty", keyFile)
		}
		return k, nil
	}
	return inlineKey, nil
}
