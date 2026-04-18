package scanner

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// RenderMasterDnsConfig produces a single-shot client_config.toml for one
// resolver probe.
//
// Two modes:
//
//  1. Template mode (opts.ConfigTemplate != ""): the user's TOML is read
//     verbatim and a small allowlist of keys is overridden line-by-line.
//     Comments and unknown keys are preserved. Missing required keys are
//     appended to the bottom in a generated section. This lets users keep
//     advanced tuning (ARQ, compression, MTU, logging) while findns still
//     enforces the keys that *must* be correct for an isolated probe.
//
//  2. Synthesised mode (opts.ConfigTemplate == ""): a minimal config is
//     built from defaults that match the upstream client_config.toml.simple.
//
// In both modes the following are *always* enforced:
//
//	DOMAINS                          = [...]                   from opts.Domains
//	ENCRYPTION_KEY                   = "..."                   from opts.Key
//	DATA_ENCRYPTION_METHOD           = N                       from opts.EncryptionMethod
//	PROTOCOL_TYPE                    = "SOCKS5"
//	LISTEN_IP                        = "127.0.0.1"
//	LISTEN_PORT                      = <listenPort>
//	SOCKS5_AUTH                      = false
//	LOCAL_DNS_ENABLED                = false
//	LOG_LEVEL                        = "ERROR"
//	RECHECK_INACTIVE_SERVERS_ENABLED = false
//	AUTO_DISABLE_TIMEOUT_SERVERS     = false
//	MTU_TEST_PARALLELISM             = 1
//	MTU_TEST_RETRIES                 = 1
//	SAVE_MTU_SERVERS_TO_FILE         = <true if MTUBisect else false>
//	MTU_SERVERS_FILE_NAME            = <mtuLogName>            (only when MTUBisect)
//	MTU_SERVERS_FILE_FORMAT          = "{IP} UP={UP_MTU} DOWN={DOWN_MTU}"
//
// These overrides exist because we run one resolver per subprocess: any
// background recheck, balancing, or auto-disable logic from the upstream
// runtime would interfere with isolated probing.
func RenderMasterDnsConfig(opts MasterDnsOpts, resolverIP string, listenPort int, mtuLogName string) (string, error) {
	if len(opts.Domains) == 0 {
		return "", fmt.Errorf("masterdns: at least one domain is required")
	}
	if opts.Key == "" {
		return "", fmt.Errorf("masterdns: encryption key is required")
	}

	encMethod := opts.EncryptionMethod
	if encMethod < 0 || encMethod > 5 {
		// Mirror upstream normalisation: invalid values fall back to XOR.
		encMethod = 1
	}

	// Every key here is enforced regardless of what the user template says.
	// SOCKS5_AUTH must be false because waitAndTestSOCKS5Connect performs a
	// no-auth handshake (method 0x00) — leaving auth enabled in a template
	// would silently fail every probe.
	overrides := map[string]string{
		"DOMAINS":                          tomlStringList(opts.Domains),
		"ENCRYPTION_KEY":                   tomlString(opts.Key),
		"DATA_ENCRYPTION_METHOD":           fmt.Sprintf("%d", encMethod),
		"PROTOCOL_TYPE":                    `"SOCKS5"`,
		"LISTEN_IP":                        `"127.0.0.1"`,
		"LISTEN_PORT":                      fmt.Sprintf("%d", listenPort),
		"SOCKS5_AUTH":                      "false",
		"LOCAL_DNS_ENABLED":                "false",
		"LOG_LEVEL":                        `"ERROR"`,
		"RECHECK_INACTIVE_SERVERS_ENABLED": "false",
		"AUTO_DISABLE_TIMEOUT_SERVERS":     "false",
		"MTU_TEST_PARALLELISM":             "1",
		"MTU_TEST_RETRIES":                 "1",
	}
	if opts.MTUBisect {
		overrides["SAVE_MTU_SERVERS_TO_FILE"] = "true"
		overrides["MTU_SERVERS_FILE_NAME"] = tomlString(mtuLogName)
		overrides["MTU_SERVERS_FILE_FORMAT"] = `"{IP} UP={UP_MTU} DOWN={DOWN_MTU}"`
	} else {
		overrides["SAVE_MTU_SERVERS_TO_FILE"] = "false"
	}

	var base string
	if opts.ConfigTemplate != "" {
		raw, err := os.ReadFile(opts.ConfigTemplate)
		if err != nil {
			return "", fmt.Errorf("reading masterdns config template %q: %w", opts.ConfigTemplate, err)
		}
		base = string(raw)
	} else {
		base = defaultMasterDnsConfig
	}

	return mergeMasterDnsConfig(base, overrides), nil
}

// mergeMasterDnsConfig walks the base TOML line-by-line. For each top-level
// key in `overrides`, the first matching assignment OUTSIDE any [section]
// table is rewritten in place. Keys not found at top level are appended at
// the end under a clearly labelled findns section. The merge is
// deliberately string-level (no TOML parser) to avoid pulling in a
// dependency and to preserve every comment the user wrote.
//
// Section awareness: once we see a `[section]` header line, we stop
// rewriting until the next header (or EOF). This protects against future
// upstream config layouts where one of our allowlist key names happens to
// also exist scoped inside a table.
func mergeMasterDnsConfig(base string, overrides map[string]string) string {
	applied := make(map[string]bool, len(overrides))

	var b strings.Builder
	b.Grow(len(base) + 1024)

	inSection := false
	for _, line := range strings.Split(base, "\n") {
		if isTomlSectionHeader(line) {
			inSection = true
			b.WriteString(line)
			b.WriteByte('\n')
			continue
		}
		if !inSection {
			if key, ok := parseTomlKey(line); ok {
				if val, hit := overrides[key]; hit && !applied[key] {
					b.WriteString(key)
					b.WriteString(" = ")
					b.WriteString(val)
					b.WriteByte('\n')
					applied[key] = true
					continue
				}
			}
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}

	// Append any keys we didn't rewrite in place.
	var leftover []string
	for k := range overrides {
		if !applied[k] {
			leftover = append(leftover, k)
		}
	}
	if len(leftover) > 0 {
		// Sort for deterministic output (helps tests, diffs, and humans).
		sortStrings(leftover)
		b.WriteString("\n# ----- findns single-shot overrides (appended) -----\n")
		for _, k := range leftover {
			b.WriteString(k)
			b.WriteString(" = ")
			b.WriteString(overrides[k])
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// tomlKeyPattern matches a top-level "KEY = ..." assignment. Allows leading
// whitespace and inline comments. Keys are conventionally ALL_CAPS in the
// upstream config so we accept letters, digits, and underscores.
var tomlKeyPattern = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=`)

func parseTomlKey(line string) (string, bool) {
	// Skip pure comments quickly to keep the merge cheap.
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", false
	}
	m := tomlKeyPattern.FindStringSubmatch(line)
	if len(m) < 2 {
		return "", false
	}
	return m[1], true
}

// isTomlSectionHeader reports whether a line starts a [section] (or
// [[array.of.tables]]) block. Once we cross one, our top-level overrides
// stop applying, so a stray scoped key with a colliding name is left alone.
func isTomlSectionHeader(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]")
}

// tomlString quotes a value as a TOML basic string with conservative
// escaping. Sufficient for keys that may contain backslashes or quotes.
func tomlString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func tomlStringList(items []string) string {
	parts := make([]string, len(items))
	for i, s := range items {
		parts[i] = tomlString(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func sortStrings(s []string) {
	// Tiny insertion sort — keeps this file dependency-free and the slices
	// here will only ever have a handful of entries.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// defaultMasterDnsConfig is the minimal baseline used when the operator
// supplies no template. Only the keys we need to ship bytes through one
// resolver in single-shot mode are included; everything else relies on the
// upstream client's built-in defaults.
const defaultMasterDnsConfig = `# Auto-generated by findns for a single-resolver MasterDnsVPN probe.
# All values below may be overridden in-place by the per-call renderer.
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = []
DATA_ENCRYPTION_METHOD = 1
ENCRYPTION_KEY = ""
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 0
SOCKS5_AUTH = false
LOCAL_DNS_ENABLED = false
LOG_LEVEL = "ERROR"
RECHECK_INACTIVE_SERVERS_ENABLED = false
AUTO_DISABLE_TIMEOUT_SERVERS = false
MTU_TEST_PARALLELISM = 1
MTU_TEST_RETRIES = 1
SAVE_MTU_SERVERS_TO_FILE = false
`
