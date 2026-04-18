package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requireSubstring is a tiny helper so tests stay terse and produce a
// readable failure when an expected fragment is missing.
func requireSubstring(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("expected substring %q in:\n%s", needle, haystack)
	}
}

func TestRenderMasterDnsConfig_Synthesised_BasicShape(t *testing.T) {
	opts := MasterDnsOpts{
		Domains:          []string{"v.example.com", "v2.example.com"},
		Key:              "supersecret",
		EncryptionMethod: 3,
	}
	cfg, err := RenderMasterDnsConfig(opts, "8.8.8.8", 30001, "mtu.log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, want := range []string{
		`DOMAINS = ["v.example.com", "v2.example.com"]`,
		`ENCRYPTION_KEY = "supersecret"`,
		`DATA_ENCRYPTION_METHOD = 3`,
		`LISTEN_IP = "127.0.0.1"`,
		`LISTEN_PORT = 30001`,
		`PROTOCOL_TYPE = "SOCKS5"`,
		`LOCAL_DNS_ENABLED = false`,
		`RECHECK_INACTIVE_SERVERS_ENABLED = false`,
		`AUTO_DISABLE_TIMEOUT_SERVERS = false`,
		`SAVE_MTU_SERVERS_TO_FILE = false`,
	} {
		requireSubstring(t, cfg, want)
	}

	// MTU file format must NOT appear when bisect is off.
	if strings.Contains(cfg, "MTU_SERVERS_FILE_FORMAT") {
		t.Fatalf("did not expect MTU_SERVERS_FILE_FORMAT without MTUBisect: %s", cfg)
	}
}

func TestRenderMasterDnsConfig_MTUBisect_EnablesFile(t *testing.T) {
	opts := MasterDnsOpts{
		Domains:          []string{"v.example.com"},
		Key:              "k",
		EncryptionMethod: 1,
		MTUBisect:        true,
	}
	cfg, err := RenderMasterDnsConfig(opts, "1.1.1.1", 30002, "mtu_results.log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireSubstring(t, cfg, `SAVE_MTU_SERVERS_TO_FILE = true`)
	requireSubstring(t, cfg, `MTU_SERVERS_FILE_NAME = "mtu_results.log"`)
	requireSubstring(t, cfg, `MTU_SERVERS_FILE_FORMAT = "{IP} UP={UP_MTU} DOWN={DOWN_MTU}"`)
}

func TestRenderMasterDnsConfig_MissingDomains(t *testing.T) {
	_, err := RenderMasterDnsConfig(MasterDnsOpts{Key: "k"}, "1.1.1.1", 1, "")
	if err == nil {
		t.Fatal("expected error for missing domains")
	}
}

func TestRenderMasterDnsConfig_MissingKey(t *testing.T) {
	_, err := RenderMasterDnsConfig(MasterDnsOpts{Domains: []string{"a"}}, "1.1.1.1", 1, "")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestRenderMasterDnsConfig_OutOfRangeEncMethod_NormalisesToXOR(t *testing.T) {
	cfg, err := RenderMasterDnsConfig(MasterDnsOpts{
		Domains:          []string{"a"},
		Key:              "k",
		EncryptionMethod: 99,
	}, "1.1.1.1", 1, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireSubstring(t, cfg, `DATA_ENCRYPTION_METHOD = 1`)
}

// Template mode: user keys must be preserved, only the allowlist gets
// rewritten in place. Comments and unknown keys survive the merge.
func TestRenderMasterDnsConfig_TemplateOverridesInPlace(t *testing.T) {
	tmp := t.TempDir()
	tplPath := filepath.Join(tmp, "client_config.toml")
	template := `# user comment, must survive
PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["old.example.com"]
ENCRYPTION_KEY = "old-key"
DATA_ENCRYPTION_METHOD = 0
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 1
SOCKS5_AUTH = false
LOG_LEVEL = "DEBUG"
RECHECK_INACTIVE_SERVERS_ENABLED = true
AUTO_DISABLE_TIMEOUT_SERVERS = true
LOCAL_DNS_ENABLED = true
MTU_TEST_PARALLELISM = 8
MTU_TEST_RETRIES = 5
SAVE_MTU_SERVERS_TO_FILE = true
# user-tuned ARQ knob, must survive untouched
ARQ_RTO_MIN_MS = 75
RX_TX_WORKERS = 4
`
	if err := os.WriteFile(tplPath, []byte(template), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	opts := MasterDnsOpts{
		Domains:          []string{"new.example.com"},
		Key:              "new-key",
		EncryptionMethod: 5,
		ConfigTemplate:   tplPath,
	}
	cfg, err := RenderMasterDnsConfig(opts, "9.9.9.9", 31000, "mtu.log")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, want := range []string{
		`DOMAINS = ["new.example.com"]`,
		`ENCRYPTION_KEY = "new-key"`,
		`DATA_ENCRYPTION_METHOD = 5`,
		`LISTEN_IP = "127.0.0.1"`,
		`LISTEN_PORT = 31000`,
		`LOG_LEVEL = "ERROR"`,
		`RECHECK_INACTIVE_SERVERS_ENABLED = false`,
		`AUTO_DISABLE_TIMEOUT_SERVERS = false`,
		`LOCAL_DNS_ENABLED = false`,
		`MTU_TEST_PARALLELISM = 1`,
		`MTU_TEST_RETRIES = 1`,
		`SAVE_MTU_SERVERS_TO_FILE = false`,
		// User keys must survive verbatim:
		`# user comment, must survive`,
		`# user-tuned ARQ knob, must survive untouched`,
		`ARQ_RTO_MIN_MS = 75`,
		`RX_TX_WORKERS = 4`,
	} {
		requireSubstring(t, cfg, want)
	}

	// Stale values must be gone after the rewrite.
	for _, gone := range []string{
		`old.example.com`,
		`old-key`,
		`LISTEN_IP = "0.0.0.0"`,
		`LISTEN_PORT = 1`,
		`LOG_LEVEL = "DEBUG"`,
		`MTU_TEST_PARALLELISM = 8`,
	} {
		if strings.Contains(cfg, gone) {
			t.Fatalf("expected %q to be rewritten away, got:\n%s", gone, cfg)
		}
	}
}

// When the template lacks a key from our allowlist, it must be appended in
// the trailer so the upstream binary still sees a valid value.
func TestRenderMasterDnsConfig_TemplateMissingKeysAreAppended(t *testing.T) {
	tmp := t.TempDir()
	tplPath := filepath.Join(tmp, "client_config.toml")
	// Template intentionally omits LISTEN_*, LOG_LEVEL, etc.
	template := "DOMAINS = []\nENCRYPTION_KEY = \"\"\n"
	if err := os.WriteFile(tplPath, []byte(template), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	cfg, err := RenderMasterDnsConfig(MasterDnsOpts{
		Domains:          []string{"a.example"},
		Key:              "k",
		EncryptionMethod: 2,
		ConfigTemplate:   tplPath,
	}, "1.1.1.1", 32000, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	requireSubstring(t, cfg, "# ----- findns single-shot overrides (appended) -----")
	requireSubstring(t, cfg, `LISTEN_IP = "127.0.0.1"`)
	requireSubstring(t, cfg, `LISTEN_PORT = 32000`)
	requireSubstring(t, cfg, `LOG_LEVEL = "ERROR"`)
	requireSubstring(t, cfg, `PROTOCOL_TYPE = "SOCKS5"`)
}

func TestTomlString_EscapesQuotesAndBackslashes(t *testing.T) {
	cases := map[string]string{
		`hello`:        `"hello"`,
		`he"llo`:       `"he\"llo"`,
		`back\slash`:   `"back\\slash"`,
		"line\nbreak":  `"line\nbreak"`,
		"":             `""`,
		`tab	inside`: `"tab\tinside"`,
	}
	for in, want := range cases {
		got := tomlString(in)
		if got != want {
			t.Errorf("tomlString(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTomlStringList(t *testing.T) {
	got := tomlStringList([]string{"a", `b"c`, "d"})
	want := `["a", "b\"c", "d"]`
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}

	// Empty list must still be valid TOML.
	if got := tomlStringList(nil); got != "[]" {
		t.Errorf("empty list got %q want []", got)
	}
}

func TestParseTomlKey(t *testing.T) {
	cases := []struct {
		in     string
		key    string
		wantOK bool
	}{
		{"DOMAINS = []", "DOMAINS", true},
		{"  LISTEN_PORT=80", "LISTEN_PORT", true},
		{"# comment", "", false},
		{"", "", false},
		{"   ", "", false},
		{"123BAD = 1", "", false}, // can't start with a digit
	}
	for _, c := range cases {
		k, ok := parseTomlKey(c.in)
		if ok != c.wantOK || k != c.key {
			t.Errorf("parseTomlKey(%q) = (%q,%v), want (%q,%v)", c.in, k, ok, c.key, c.wantOK)
		}
	}
}

func TestSortStrings(t *testing.T) {
	in := []string{"c", "a", "b"}
	sortStrings(in)
	for i, v := range []string{"a", "b", "c"} {
		if in[i] != v {
			t.Fatalf("got %v", in)
		}
	}
}

// SOCKS5_AUTH must always be forced to false because waitAndTestSOCKS5Connect
// performs a no-auth handshake. Regression guard against the bug where the
// override map omitted SOCKS5_AUTH and a user template with `SOCKS5_AUTH = true`
// silently broke every probe.
func TestRenderMasterDnsConfig_TemplateForcesSOCKS5AuthOff(t *testing.T) {
	tmp := t.TempDir()
	tplPath := filepath.Join(tmp, "client_config.toml")
	if err := os.WriteFile(tplPath, []byte("SOCKS5_AUTH = true\n"), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	cfg, err := RenderMasterDnsConfig(MasterDnsOpts{
		Domains:        []string{"v.example.com"},
		Key:            "k",
		ConfigTemplate: tplPath,
	}, "1.1.1.1", 1, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireSubstring(t, cfg, "SOCKS5_AUTH = false")
	if strings.Contains(cfg, "SOCKS5_AUTH = true") {
		t.Fatalf("SOCKS5_AUTH = true must be rewritten away, got:\n%s", cfg)
	}
}

// Top-level keys must be rewritten, but identically-named keys scoped inside
// a [section] block must be left alone. Today's upstream config is flat, but
// this guards against a future schema change biting us silently.
func TestRenderMasterDnsConfig_SectionScopedKeysPreserved(t *testing.T) {
	tmp := t.TempDir()
	tplPath := filepath.Join(tmp, "client_config.toml")
	template := `LISTEN_PORT = 9999
PROTOCOL_TYPE = "SOCKS5"

[advanced]
LISTEN_PORT = 7777
LOG_LEVEL = "DEBUG"

[advanced.nested]
LOG_LEVEL = "TRACE"
`
	if err := os.WriteFile(tplPath, []byte(template), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	cfg, err := RenderMasterDnsConfig(MasterDnsOpts{
		Domains:        []string{"v.example.com"},
		Key:            "k",
		ConfigTemplate: tplPath,
	}, "1.1.1.1", 31337, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Top-level LISTEN_PORT was rewritten to our chosen value.
	requireSubstring(t, cfg, "LISTEN_PORT = 31337")
	// Section-scoped LISTEN_PORT and LOG_LEVEL must survive untouched.
	requireSubstring(t, cfg, "[advanced]")
	requireSubstring(t, cfg, "LISTEN_PORT = 7777")
	requireSubstring(t, cfg, `LOG_LEVEL = "DEBUG"`)
	requireSubstring(t, cfg, "[advanced.nested]")
	requireSubstring(t, cfg, `LOG_LEVEL = "TRACE"`)
	// Top-level LOG_LEVEL did not exist, so it lands in the appended trailer.
	requireSubstring(t, cfg, "# ----- findns single-shot overrides (appended) -----")
	requireSubstring(t, cfg, `LOG_LEVEL = "ERROR"`)
}

func TestIsTomlSectionHeader(t *testing.T) {
	cases := map[string]bool{
		"[section]":         true,
		"  [section]  ":     true,
		"[a.b.c]":           true,
		"[[array.tables]]":  true,
		"KEY = [array]":     false,
		"# [comment.like]":  false,
		"":                  false,
		"   ":               false,
		"[unterminated":     false,
		`KEY = "[brackets]"`: false,
	}
	for in, want := range cases {
		if got := isTomlSectionHeader(in); got != want {
			t.Errorf("isTomlSectionHeader(%q) = %v, want %v", in, got, want)
		}
	}
}
