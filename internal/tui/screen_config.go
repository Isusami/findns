package tui

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/SamNet-dev/findns/internal/binutil"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Text input indices (order in configInputs slice) ──
const (
	txtDomain = iota
	txtPubkey
	txtCert
	txtOutput
	txtWorkers
	txtTimeout
	txtCount
	txtEDNSSize
	txtQuerySize
	txtE2ETimeout
	txtMDDomains
	txtMDKey
	txtMDKeyFile
	txtMDEncMethod
	txtMDConfig
	numTextInputs
)

// ── Logical field IDs (not positional — used for identification) ──
type fieldID int

const (
	fDomain fieldID = iota
	fOutput
	fWorkers
	fTimeout
	fCount
	fSkipPing
	fSkipNXD
	fEDNS
	fEDNSSize
	fQuerySize
	fE2E    // toggle: enables/disables e2e section
	fPubkey // e2e fields below
	fCert
	fE2ETimeout
	// MasterDnsVPN e2e block (only shown when fE2E is on)
	fMDDomains
	fMDKey
	fMDKeyFile
	fMDEncMethod
	fMDConfig
	fMDMTUBisect
	fStart
)

type fieldDef struct {
	id    fieldID
	label string
	group string
	help  string
	// txtIdx maps to configInputs index; -1 for toggles/button
	txtIdx int
}

// allFields defines all possible fields. Visibility is computed dynamically.
var allFields = []fieldDef{
	{fDomain, "Domain", "Tunnel", "Your tunnel domain (e.g. t.example.com). Leave empty for basic resolver testing.", txtDomain},
	{fOutput, "Output", "General", "Where to save results. JSON format with all metrics and rankings.", txtOutput},
	{fWorkers, "Workers", "", "Number of concurrent workers. Higher = faster but more network load.", txtWorkers},
	{fTimeout, "Timeout (s)", "", "Seconds to wait per resolver per check before marking it as failed.", txtTimeout},
	{fCount, "Count", "", "Number of attempts per resolver. Higher = more accurate but slower.", txtCount},
	{fSkipPing, "Skip Ping", "Options", "Skip ICMP ping step. Useful if your network blocks outbound ping.", -1},
	{fSkipNXD, "Skip NXDOMAIN", "", "Skip NXDOMAIN hijack detection. Checks if resolver fakes responses.", -1},
	{fEDNS, "EDNS Check", "", "Test EDNS0 payload size support. Important for DNS tunneling throughput.", -1},
	{fEDNSSize, "EDNS Size", "", "EDNS0 UDP payload size in bytes. Larger = better throughput, lower if fragmented.", txtEDNSSize},
	{fQuerySize, "Query Size", "", "Cap upstream DNS query payload size (dnstt -mtu). Default 50 works best on filtered networks. Use 0 for max.", txtQuerySize},
	{fE2E, "E2E Testing", "E2E (end-to-end tunnel test)", "Enable end-to-end tunnel tests. Requires tunnel client binaries.", -1},
	{fPubkey, "Pubkey", "", "Hex public key for dnstt. Requires dnstt-client in PATH.", txtPubkey},
	{fCert, "Cert", "", "Path to slipstream TLS cert. Requires slipstream-client in PATH.", txtCert},
	{fE2ETimeout, "E2E Timeout (s)", "", "Seconds to wait for each e2e tunnel connectivity test.", txtE2ETimeout},
	{fMDDomains, "MasterDns Domains", "MasterDnsVPN", "Comma-separated tunnel domains (e.g. w.example.com,w.example2.com). Requires masterdnsvpn-client.", txtMDDomains},
	{fMDKey, "MasterDns Key", "", "Inline shared encryption key. Prefer Key File for anything you don't want in shell history.", txtMDKey},
	{fMDKeyFile, "MasterDns Key File", "", "Path to a file containing the encryption key (single line). Takes precedence over inline key.", txtMDKeyFile},
	{fMDEncMethod, "MasterDns Method", "", "Encryption method 0..5: 0=None 1=XOR 2=ChaCha20 3=AES-128-GCM 4=AES-192-GCM 5=AES-256-GCM. Must match server.", txtMDEncMethod},
	{fMDConfig, "MasterDns Config", "", "Optional path to template client_config.toml. Auto-detected next to findns if left empty.", txtMDConfig},
	{fMDMTUBisect, "MasterDns MTU Bisect", "", "Also collect upstream/downstream MTU per resolver (slower, adds mdvpn_up_mtu/mdvpn_down_mtu metrics).", -1},
	{fStart, "Start Scan", "", "Run the scan with the settings above.", -1},
}

// e2eSubFields are only shown when E2E toggle is on. The MasterDnsVPN
// block is part of the E2E section: it's only meaningful when the user
// has opted into E2E testing, since it's another tunnel client.
var e2eSubFields = map[fieldID]bool{
	fPubkey: true, fCert: true, fE2ETimeout: true,
	fMDDomains: true, fMDKey: true, fMDKeyFile: true,
	fMDEncMethod: true, fMDConfig: true, fMDMTUBisect: true,
}

// visibleFields returns the currently visible field list based on config state.
func visibleFields(cfg ScanConfig) []fieldDef {
	var out []fieldDef
	for _, f := range allFields {
		if e2eSubFields[f.id] && !cfg.E2E {
			continue
		}
		// slipstream-client has no Windows binary — hide Cert field on Windows
		if f.id == fCert && runtime.GOOS == "windows" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func initConfigInputs() []textinput.Model {
	inputs := make([]textinput.Model, numTextInputs)

	inputs[txtDomain] = textinput.New()
	inputs[txtDomain].Placeholder = "t.example.com"
	inputs[txtDomain].CharLimit = 256

	inputs[txtPubkey] = textinput.New()
	inputs[txtPubkey].Placeholder = "hex pubkey"
	inputs[txtPubkey].CharLimit = 256

	inputs[txtCert] = textinput.New()
	inputs[txtCert].Placeholder = "cert path"
	inputs[txtCert].CharLimit = 512

	inputs[txtOutput] = textinput.New()
	inputs[txtOutput].Placeholder = "results.json"
	inputs[txtOutput].SetValue("results.json")
	inputs[txtOutput].CharLimit = 256

	inputs[txtWorkers] = textinput.New()
	inputs[txtWorkers].Placeholder = "50"
	inputs[txtWorkers].SetValue("50")
	inputs[txtWorkers].CharLimit = 5

	inputs[txtTimeout] = textinput.New()
	inputs[txtTimeout].Placeholder = "3"
	inputs[txtTimeout].SetValue("3")
	inputs[txtTimeout].CharLimit = 3

	inputs[txtCount] = textinput.New()
	inputs[txtCount].Placeholder = "3"
	inputs[txtCount].SetValue("3")
	inputs[txtCount].CharLimit = 3

	inputs[txtEDNSSize] = textinput.New()
	inputs[txtEDNSSize].Placeholder = "1232"
	inputs[txtEDNSSize].SetValue("1232")
	inputs[txtEDNSSize].CharLimit = 4

	inputs[txtQuerySize] = textinput.New()
	inputs[txtQuerySize].Placeholder = "50"
	inputs[txtQuerySize].SetValue("50")
	inputs[txtQuerySize].CharLimit = 4

	inputs[txtE2ETimeout] = textinput.New()
	inputs[txtE2ETimeout].Placeholder = "30"
	inputs[txtE2ETimeout].SetValue("30")
	inputs[txtE2ETimeout].CharLimit = 3

	inputs[txtMDDomains] = textinput.New()
	inputs[txtMDDomains].Placeholder = "w.example.com, w.example2.com"
	inputs[txtMDDomains].CharLimit = 1024

	inputs[txtMDKey] = textinput.New()
	inputs[txtMDKey].Placeholder = "shared encryption key"
	inputs[txtMDKey].CharLimit = 256
	inputs[txtMDKey].EchoMode = textinput.EchoPassword

	inputs[txtMDKeyFile] = textinput.New()
	inputs[txtMDKeyFile].Placeholder = "mdkey.txt"
	inputs[txtMDKeyFile].CharLimit = 512

	inputs[txtMDEncMethod] = textinput.New()
	inputs[txtMDEncMethod].Placeholder = "1"
	inputs[txtMDEncMethod].SetValue("1")
	inputs[txtMDEncMethod].CharLimit = 1

	inputs[txtMDConfig] = textinput.New()
	inputs[txtMDConfig].Placeholder = "client_config.toml (auto-detected)"
	inputs[txtMDConfig].CharLimit = 512

	inputs[txtDomain].Focus()
	return inputs
}

func isToggle(id fieldID) bool {
	return id == fSkipPing || id == fSkipNXD || id == fEDNS || id == fE2E || id == fMDMTUBisect
}

func currentField(m Model) fieldDef {
	vf := visibleFields(m.config)
	if m.cursor >= 0 && m.cursor < len(vf) {
		return vf[m.cursor]
	}
	return fieldDef{id: fStart}
}

func updateConfig(m Model, msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		vf := visibleFields(m.config)
		n := len(vf)

		switch msg.String() {
		case "tab", "down":
			m.cursor++
			if m.cursor >= n {
				m.cursor = 0
			}
			return m, focusConfigInput(&m)
		case "shift+tab", "up":
			m.cursor--
			if m.cursor < 0 {
				m.cursor = n - 1
			}
			return m, focusConfigInput(&m)
		case "enter":
			fd := currentField(m)
			if fd.id == fStart {
				return applyConfig(m)
			}
			if isToggle(fd.id) {
				toggleField(&m, fd.id)
			}
			return m, nil
		case " ":
			fd := currentField(m)
			if isToggle(fd.id) {
				toggleField(&m, fd.id)
				return m, nil
			}
			return updateConfigTextInput(m, msg)
		case "backspace":
			fd := currentField(m)
			if fd.txtIdx < 0 {
				// Toggle/button field: go back
				m.screen = screenInput
				m.cursor = 0
				m.err = nil
				return m, nil
			}
			if m.configInputs[fd.txtIdx].Value() == "" {
				m.screen = screenInput
				m.cursor = 0
				m.err = nil
				return m, nil
			}
			return updateConfigTextInput(m, msg)
		case "left":
			return updateConfigTextInput(m, msg)
		default:
			return updateConfigTextInput(m, msg)
		}
	}
	return m, nil
}

func toggleField(m *Model, id fieldID) {
	switch id {
	case fSkipPing:
		m.config.SkipPing = !m.config.SkipPing
	case fSkipNXD:
		m.config.SkipNXDomain = !m.config.SkipNXDomain
	case fEDNS:
		m.config.EDNS = !m.config.EDNS
	case fMDMTUBisect:
		m.config.MasterDnsMTUBisect = !m.config.MasterDnsMTUBisect
	case fE2E:
		m.config.E2E = !m.config.E2E
		// Keep cursor on the E2E toggle after field list changes
		for i, f := range visibleFields(m.config) {
			if f.id == fE2E {
				m.cursor = i
				break
			}
		}
	}
}

func updateConfigTextInput(m Model, msg tea.Msg) (Model, tea.Cmd) {
	fd := currentField(m)
	if fd.txtIdx >= 0 {
		var cmd tea.Cmd
		m.configInputs[fd.txtIdx], cmd = m.configInputs[fd.txtIdx].Update(msg)
		return m, cmd
	}
	return m, nil
}

func focusConfigInput(m *Model) tea.Cmd {
	for i := range m.configInputs {
		m.configInputs[i].Blur()
	}
	fd := currentField(*m)
	if fd.txtIdx >= 0 {
		m.configInputs[fd.txtIdx].Focus()
		return m.configInputs[fd.txtIdx].Cursor.BlinkCmd()
	}
	return nil
}

func applyConfig(m Model) (Model, tea.Cmd) {
	m.config.Domain = strings.TrimSpace(m.configInputs[txtDomain].Value())
	m.config.Pubkey = strings.TrimSpace(m.configInputs[txtPubkey].Value())
	m.config.Cert = strings.TrimSpace(m.configInputs[txtCert].Value())
	m.config.OutputFile = strings.TrimSpace(m.configInputs[txtOutput].Value())

	if v, err := strconv.Atoi(m.configInputs[txtWorkers].Value()); err == nil && v > 0 {
		m.config.Workers = v
	}
	if v, err := strconv.Atoi(m.configInputs[txtTimeout].Value()); err == nil && v > 0 {
		m.config.Timeout = v
	}
	if v, err := strconv.Atoi(m.configInputs[txtCount].Value()); err == nil && v > 0 {
		m.config.Count = v
	}
	if v, err := strconv.Atoi(m.configInputs[txtEDNSSize].Value()); err == nil && v > 0 {
		m.config.EDNSSize = v
	}
	if v, err := strconv.Atoi(m.configInputs[txtQuerySize].Value()); err == nil && v >= 0 {
		m.config.QuerySize = v
	}
	if v, err := strconv.Atoi(m.configInputs[txtE2ETimeout].Value()); err == nil && v > 0 {
		m.config.E2ETimeout = v
	}

	m.config.MasterDnsDomains = strings.TrimSpace(m.configInputs[txtMDDomains].Value())
	m.config.MasterDnsKey = strings.TrimSpace(m.configInputs[txtMDKey].Value())
	m.config.MasterDnsKeyFile = strings.TrimSpace(m.configInputs[txtMDKeyFile].Value())
	m.config.MasterDnsConfigTemplate = strings.TrimSpace(m.configInputs[txtMDConfig].Value())
	if v, err := strconv.Atoi(m.configInputs[txtMDEncMethod].Value()); err == nil && v >= 0 && v <= 5 {
		m.config.MasterDnsEncryptionMethod = v
	}

	// Clear all e2e fields if e2e is disabled
	if !m.config.E2E {
		m.config.Pubkey = ""
		m.config.Cert = ""
		m.configInputs[txtPubkey].SetValue("")
		m.configInputs[txtCert].SetValue("")
		m.config.MasterDnsDomains = ""
		m.config.MasterDnsKey = ""
		m.config.MasterDnsKeyFile = ""
		m.config.MasterDnsConfigTemplate = ""
		m.config.MasterDnsMTUBisect = false
		m.configInputs[txtMDDomains].SetValue("")
		m.configInputs[txtMDKey].SetValue("")
		m.configInputs[txtMDKeyFile].SetValue("")
		m.configInputs[txtMDConfig].SetValue("")
	}

	if m.config.OutputFile == "" {
		m.config.OutputFile = "results.json"
	}

	m.screen = screenRunning
	m.cursor = 0
	return m, m.startScan()
}

func viewConfig(m Model) string {
	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(titleStyle.Render("  Scan Configuration"))
	b.WriteString("\n")
	mode := "UDP"
	if m.config.DoH {
		mode = "DoH"
	}
	b.WriteString(dimStyle.Render(fmt.Sprintf("  %d resolvers loaded  •  Mode: %s", len(m.ips), mode)))
	b.WriteString("\n\n")

	if m.err != nil {
		b.WriteString(redStyle.Render(fmt.Sprintf("  Error: %v", m.err)))
		b.WriteString("\n\n")
	}

	vf := visibleFields(m.config)
	lastGroup := ""

	for i, fd := range vf {
		// Section header
		if fd.group != "" && fd.group != lastGroup {
			if lastGroup != "" {
				b.WriteString("\n")
			}
			b.WriteString(dimStyle.Render(fmt.Sprintf("  — %s", fd.group)))
			b.WriteString("\n")
			lastGroup = fd.group
		}

		cursor := "  "
		lStyle := labelStyle
		if i == m.cursor {
			cursor = "> "
			lStyle = labelStyle.Foreground(lipgloss.Color("14"))
		}

		// Start button gets special rendering
		if fd.id == fStart {
			b.WriteString("\n")
			if i == m.cursor {
				b.WriteString(fmt.Sprintf("  %s%s\n", cursor, buttonStyle.Render("Start Scan")))
			} else {
				b.WriteString(fmt.Sprintf("  %s%s\n", cursor, dimStyle.Render("[ Start Scan ]")))
			}
			continue
		}

		var value string
		if isToggle(fd.id) {
			value = toggleView(getToggleValue(m, fd.id))
		} else {
			value = m.configInputs[fd.txtIdx].View()
		}

		b.WriteString(fmt.Sprintf("  %s%-16s %s\n", cursor, lStyle.Render(fd.label), value))

		// Show binary status after E2E toggle when enabled
		if fd.id == fE2E && m.config.E2E {
			b.WriteString(binaryStatus())
		}
	}

	// Context-sensitive help
	b.WriteString("\n")
	fd := currentField(m)
	b.WriteString(dimStyle.Render("  " + fd.help))
	b.WriteString("\n")

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  ↑/↓ navigate  tab next  space toggle  enter confirm  ctrl+c quit"))
	b.WriteString("\n")

	return b.String()
}

func getToggleValue(m Model, id fieldID) bool {
	switch id {
	case fSkipPing:
		return m.config.SkipPing
	case fSkipNXD:
		return m.config.SkipNXDomain
	case fEDNS:
		return m.config.EDNS
	case fE2E:
		return m.config.E2E
	case fMDMTUBisect:
		return m.config.MasterDnsMTUBisect
	}
	return false
}

func binaryStatus() string {
	var b strings.Builder
	bins := []struct {
		name string
		bin  string
	}{
		{"dnstt-client", "dnstt-client"},
		{"masterdnsvpn-client", "masterdnsvpn-client"},
	}
	// slipstream-client only available on Linux/macOS
	if runtime.GOOS != "windows" {
		bins = append(bins, struct {
			name string
			bin  string
		}{"slipstream-client", "slipstream-client"})
	}
	for _, bin := range bins {
		path, err := binutil.Find(bin.bin)
		if err != nil {
			b.WriteString(fmt.Sprintf("      %s  %s\n", redStyle.Render("✘"), dimStyle.Render(bin.name+" not found")))
		} else {
			b.WriteString(fmt.Sprintf("      %s  %s\n", greenStyle.Render("✔"), dimStyle.Render(bin.name+" → "+path)))
		}
	}
	return b.String()
}

func toggleView(v bool) string {
	if v {
		return greenStyle.Render("[x]")
	}
	return dimStyle.Render("[ ]")
}
