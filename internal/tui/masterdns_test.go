package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseMasterDnsDomains exercises the TUI input parser used to
// convert the comma/pipe/semicolon-separated text input into a clean
// slice of tunnel domains for scanner.MasterDnsOpts.
func TestParseMasterDnsDomains(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"single", "w.example.com", []string{"w.example.com"}},
		{"comma", "a.example.com, b.example.com", []string{"a.example.com", "b.example.com"}},
		{"pipe", "a.example.com|b.example.com", []string{"a.example.com", "b.example.com"}},
		{"semicolon mixed", "a.example.com; b.example.com , c.example.com",
			[]string{"a.example.com", "b.example.com", "c.example.com"}},
		{"newlines", "a.example.com\nb.example.com", []string{"a.example.com", "b.example.com"}},
		{"trailing separators", ",a.example.com,,b.example.com,",
			[]string{"a.example.com", "b.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMasterDnsDomains(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("len mismatch: got %v want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("idx %d: got %q want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestNewModelWithConfig_PrepopulatesMasterDns proves the constructor
// copies every MasterDns* ScanConfig field into the matching
// configInputs slot, so the TUI starts with the right values when
// launched from CLI flags.
func TestNewModelWithConfig_PrepopulatesMasterDns(t *testing.T) {
	cfg := ScanConfig{
		MasterDnsDomains:          "v1.example.com,v2.example.com",
		MasterDnsKey:              "supersecret",
		MasterDnsKeyFile:          "/tmp/mdkey.txt",
		MasterDnsEncryptionMethod: 3,
		MasterDnsConfigTemplate:   "/tmp/client_config.toml",
		MasterDnsMTUBisect:        true,
		E2E:                       true,
	}
	m := NewModelWithConfig(cfg)

	checks := map[int]string{
		txtMDDomains:   "v1.example.com,v2.example.com",
		txtMDKey:       "supersecret",
		txtMDKeyFile:   "/tmp/mdkey.txt",
		txtMDConfig:    "/tmp/client_config.toml",
		txtMDEncMethod: "3",
	}
	for idx, want := range checks {
		if got := m.configInputs[idx].Value(); got != want {
			t.Errorf("input %d: got %q want %q", idx, got, want)
		}
	}
	if !m.config.MasterDnsMTUBisect {
		t.Errorf("MTUBisect lost during NewModelWithConfig")
	}
	if !m.config.E2E {
		t.Errorf("E2E flag lost during NewModelWithConfig")
	}
}

// TestVisibleFields_MasterDnsGating asserts the masterdns block is
// hidden until the E2E toggle is on, and visible afterwards. This is
// what keeps the config screen short for users who only want a basic
// resolver scan.
func TestVisibleFields_MasterDnsGating(t *testing.T) {
	hasMD := func(cfg ScanConfig) bool {
		for _, f := range visibleFields(cfg) {
			switch f.id {
			case fMDDomains, fMDKey, fMDKeyFile,
				fMDEncMethod, fMDConfig, fMDMTUBisect:
				return true
			}
		}
		return false
	}
	if hasMD(ScanConfig{E2E: false}) {
		t.Errorf("masterdns fields should be hidden when E2E is off")
	}
	if !hasMD(ScanConfig{E2E: true}) {
		t.Errorf("masterdns fields should be visible when E2E is on")
	}
}

// TestApplyConfig_ClearsMasterDnsWhenE2EOff makes sure flipping E2E
// off wipes the masterdns inputs, matching the existing behaviour for
// Pubkey/Cert. This prevents leftover state from quietly enabling an
// e2e/masterdns step the user thought they had turned off.
func TestApplyConfig_ClearsMasterDnsWhenE2EOff(t *testing.T) {
	cfg := ScanConfig{
		MasterDnsDomains:          "v1.example.com",
		MasterDnsKey:              "secret",
		MasterDnsKeyFile:          "/tmp/k",
		MasterDnsEncryptionMethod: 2,
		MasterDnsConfigTemplate:   "/tmp/c.toml",
		MasterDnsMTUBisect:        true,
		E2E:                       false,
	}
	m := NewModelWithConfig(cfg)
	m.ips = []string{"1.1.1.1"}
	m, _ = applyConfig(m)

	if m.config.MasterDnsDomains != "" || m.config.MasterDnsKey != "" ||
		m.config.MasterDnsKeyFile != "" || m.config.MasterDnsConfigTemplate != "" ||
		m.config.MasterDnsMTUBisect {
		t.Fatalf("masterdns fields not cleared when E2E off: %+v", m.config)
	}
}

// TestApplyConfig_ReadsMasterDnsBackWhenE2EOn proves applyConfig
// faithfully copies the focused text-input values into ScanConfig
// when E2E is enabled (the path that actually reaches buildSteps).
func TestApplyConfig_ReadsMasterDnsBackWhenE2EOn(t *testing.T) {
	cfg := ScanConfig{E2E: true, MasterDnsEncryptionMethod: 1}
	m := NewModelWithConfig(cfg)
	m.ips = []string{"1.1.1.1"}
	m.configInputs[txtMDDomains].SetValue("a.example.com, b.example.com")
	m.configInputs[txtMDKey].SetValue("inline-key")
	m.configInputs[txtMDKeyFile].SetValue("/tmp/key")
	m.configInputs[txtMDEncMethod].SetValue("4")
	m.configInputs[txtMDConfig].SetValue("/tmp/template.toml")
	m.config.MasterDnsMTUBisect = true

	m, _ = applyConfig(m)

	if m.config.MasterDnsDomains != "a.example.com, b.example.com" {
		t.Errorf("Domains: got %q", m.config.MasterDnsDomains)
	}
	if m.config.MasterDnsKey != "inline-key" {
		t.Errorf("Key: got %q", m.config.MasterDnsKey)
	}
	if m.config.MasterDnsKeyFile != "/tmp/key" {
		t.Errorf("KeyFile: got %q", m.config.MasterDnsKeyFile)
	}
	if m.config.MasterDnsConfigTemplate != "/tmp/template.toml" {
		t.Errorf("Template: got %q", m.config.MasterDnsConfigTemplate)
	}
	if m.config.MasterDnsEncryptionMethod != 4 {
		t.Errorf("EncMethod: got %d", m.config.MasterDnsEncryptionMethod)
	}
	if !m.config.MasterDnsMTUBisect {
		t.Errorf("MTUBisect lost")
	}
}

// TestBuildSteps_AppendsMasterDnsStep validates the wiring from
// ScanConfig through buildSteps into a real scanner.Step using the
// locally-staged masterdnsvpn-client binary. Skipped when the binary
// isn't available next to the test (CI without artifacts).
func TestBuildSteps_AppendsMasterDnsStep(t *testing.T) {
	repoRoot := findRepoRoot(t)
	bin := filepath.Join(repoRoot, "masterdnsvpn-client")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("masterdnsvpn-client not staged at %s: %v", bin, err)
	}
	keyFile := filepath.Join(repoRoot, "mdkey.txt")
	if _, err := os.Stat(keyFile); err != nil {
		t.Skipf("mdkey.txt not staged at %s: %v", keyFile, err)
	}

	// Tell binutil.Find to look in the repo root by adjusting PATH so
	// the resolution is deterministic regardless of cwd.
	t.Setenv("PATH", repoRoot+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfg := ScanConfig{
		Workers:                   4,
		Timeout:                   3,
		Count:                     1,
		E2ETimeout:                10,
		EDNSSize:                  1232,
		MasterDnsDomains:          "v1.example.com,v2.example.com",
		MasterDnsKeyFile:          keyFile,
		MasterDnsEncryptionMethod: 1,
	}
	steps, err := buildSteps(cfg)
	if err != nil {
		t.Fatalf("buildSteps returned error: %v", err)
	}
	var names []string
	for _, s := range steps {
		names = append(names, s.Name)
	}
	if len(names) == 0 || names[len(names)-1] != "e2e/masterdns" {
		t.Fatalf("expected last step to be e2e/masterdns, got %v", names)
	}
}

// TestBuildSteps_SkipsMasterDnsWhenIncomplete confirms that providing
// only domains (no key/keyfile) does NOT add the masterdns step, so
// users who type a domain by accident don't get a confusing error.
func TestBuildSteps_SkipsMasterDnsWhenIncomplete(t *testing.T) {
	cfg := ScanConfig{
		Workers:          4,
		Timeout:          3,
		Count:            1,
		E2ETimeout:       10,
		MasterDnsDomains: "v1.example.com",
		// No Key/KeyFile -> step must be skipped.
	}
	steps, err := buildSteps(cfg)
	if err != nil {
		t.Fatalf("buildSteps returned error: %v", err)
	}
	for _, s := range steps {
		if s.Name == "e2e/masterdns" {
			t.Fatalf("e2e/masterdns step should not be present without a key")
		}
	}
}

// findRepoRoot walks up from the test file location until it finds
// go.mod. Used by tests that need to load locally-staged artifacts
// (binaries, key files) outside the package directory.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found from %s", dir)
		}
		dir = parent
	}
}

// Compile-time guard: keep the masterdns field IDs grouped so future
// edits to allFields don't accidentally drop one. Catches the easy
// "added a field but forgot to register it" mistake.
func TestAllFields_MasterDnsBlockComplete(t *testing.T) {
	want := map[fieldID]bool{
		fMDDomains: false, fMDKey: false, fMDKeyFile: false,
		fMDEncMethod: false, fMDConfig: false, fMDMTUBisect: false,
	}
	for _, f := range allFields {
		if _, ok := want[f.id]; ok {
			want[f.id] = true
		}
	}
	for id, present := range want {
		if !present {
			t.Errorf("fieldID %d (masterdns block) missing from allFields", id)
		}
	}
	// Sanity: section header ordering — first MD field should belong
	// to the "MasterDnsVPN" group.
	for _, f := range allFields {
		if f.id == fMDDomains {
			if !strings.Contains(f.group, "MasterDnsVPN") {
				t.Errorf("fMDDomains group is %q, expected MasterDnsVPN", f.group)
			}
			break
		}
	}
}
