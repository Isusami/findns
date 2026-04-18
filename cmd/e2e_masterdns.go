package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/SamNet-dev/findns/internal/scanner"
	"github.com/spf13/cobra"
)

var e2eMasterDnsCmd = &cobra.Command{
	Use:   "masterdns",
	Short: "Test e2e connectivity through MasterDnsVPN SOCKS5 tunnel",
	Long: `Probe each resolver by spawning the masterdnsvpn-client binary
against a single-resolver, single-shot client_config.toml and driving a
real SOCKS5 CONNECT through the tunnel. Resolvers that complete the
handshake are recorded with mdvpn_e2e_ms.

Either --masterdns-key or --masterdns-key-file must be supplied. The file
takes precedence when both are set. At least one --masterdns-domain is
required.

If a 'client_config.toml' file sits next to the findns binary, it is used
as a base template and only the must-be-correct keys (DOMAINS, key,
encryption method, LISTEN_*, single-shot safety knobs) are overridden.`,
	RunE: runE2EMasterDns,
}

func init() {
	e2eMasterDnsCmd.Flags().StringSlice("masterdns-domain", nil, "tunnel domain (repeatable; matches upstream DOMAINS = [...])")
	e2eMasterDnsCmd.Flags().String("masterdns-key", "", "shared encryption key (matches server's encrypt_key.txt)")
	e2eMasterDnsCmd.Flags().String("masterdns-key-file", "", "path to encryption key file (takes precedence over --masterdns-key)")
	e2eMasterDnsCmd.Flags().Int("masterdns-encryption-method", 1, "encryption method 0..5 (0=None,1=XOR,2=ChaCha20,3=AES-128-GCM,4=AES-192-GCM,5=AES-256-GCM)")
	e2eMasterDnsCmd.Flags().String("masterdns-config", "", "path to template client_config.toml (auto-detected next to findns)")
	e2eMasterDnsCmd.Flags().Bool("masterdns-mtu-bisect", false, "additionally collect mdvpn_up_mtu / mdvpn_down_mtu (slower)")
	e2eCmd.AddCommand(e2eMasterDnsCmd)
}

func runE2EMasterDns(cmd *cobra.Command, args []string) error {
	domains, _ := cmd.Flags().GetStringSlice("masterdns-domain")
	inlineKey, _ := cmd.Flags().GetString("masterdns-key")
	keyFile, _ := cmd.Flags().GetString("masterdns-key-file")
	encMethod, _ := cmd.Flags().GetInt("masterdns-encryption-method")
	cfgTemplate, _ := cmd.Flags().GetString("masterdns-config")
	mtuBisect, _ := cmd.Flags().GetBool("masterdns-mtu-bisect")

	opts, err := buildMasterDnsOpts(domains, inlineKey, keyFile, encMethod, cfgTemplate, mtuBisect)
	if err != nil {
		return err
	}

	bin, err := findBinary("masterdnsvpn-client")
	if err != nil {
		return err
	}

	ips, err := loadInput()
	if err != nil {
		return err
	}

	dur := time.Duration(e2eTimeout) * time.Second
	ports := scanner.PortPool(30000, workers)
	check := scanner.MasterDnsCheckBin(bin, opts, ports)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	scanner.ResetE2EDiagnostic()
	start := time.Now()
	results := scanner.RunPoolCtx(ctx, ips, workers, dur, check, newProgress("e2e/masterdns"))
	elapsed := time.Since(start)

	if ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "\n\u26a0 Interrupted \u2014 saving partial results\n")
	}
	if diag := scanner.E2EDiagnostic(); diag != "" {
		fmt.Fprintf(os.Stderr, "  diagnostic: %s\n", diag)
	}

	return writeReport("e2e/masterdns", results, elapsed, "mdvpn_e2e_ms")
}

// buildMasterDnsOpts validates flag combinations, resolves the encryption
// key (file beats inline), auto-detects a sibling client_config.toml when
// no template is given, and warns when the chosen encryption method is
// weaker than ChaCha20.
func buildMasterDnsOpts(domains []string, inlineKey, keyFile string, encMethod int, cfgTemplate string, mtuBisect bool) (scanner.MasterDnsOpts, error) {
	if len(domains) == 0 {
		return scanner.MasterDnsOpts{}, fmt.Errorf("--masterdns-domain is required (at least one)")
	}
	if inlineKey == "" && keyFile == "" {
		return scanner.MasterDnsOpts{}, fmt.Errorf("--masterdns-key or --masterdns-key-file is required")
	}
	key, err := scanner.LoadMasterDnsKey(inlineKey, keyFile)
	if err != nil {
		return scanner.MasterDnsOpts{}, err
	}
	if encMethod < 0 || encMethod > 5 {
		return scanner.MasterDnsOpts{}, fmt.Errorf("--masterdns-encryption-method must be 0..5 (got %d)", encMethod)
	}
	if encMethod < 2 {
		fmt.Fprintf(os.Stderr, "  %s\u26a0 weak encryption method %d (None/XOR) \u2014 fine for scanning, NOT for production%s\n",
			colorYellow, encMethod, colorReset)
	}

	if cfgTemplate == "" {
		// Auto-detect: client_config.toml next to the running findns binary.
		if exe, err := os.Executable(); err == nil {
			candidate := filepath.Join(filepath.Dir(exe), "client_config.toml")
			if _, err := os.Stat(candidate); err == nil {
				cfgTemplate = candidate
				fmt.Fprintf(os.Stderr, "  auto-detected masterdns config template: %s\n", candidate)
			}
		}
	} else {
		if _, err := os.Stat(cfgTemplate); err != nil {
			return scanner.MasterDnsOpts{}, fmt.Errorf("--masterdns-config %q: %w", cfgTemplate, err)
		}
	}

	return scanner.MasterDnsOpts{
		Domains:          domains,
		Key:              key,
		EncryptionMethod: encMethod,
		ConfigTemplate:   cfgTemplate,
		MTUBisect:        mtuBisect,
	}, nil
}
