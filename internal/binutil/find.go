// Package binutil provides helpers for locating companion binaries.
package binutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// platformVariants returns the names to search for a given binary.
// It includes the exact name plus platform-specific variants so users
// can use the release filename (e.g. dnstt-client-linux,
// masterdnsvpn-client-darwin-arm64) without renaming.
//
// Order matters: more specific variants are tried first so that when
// multiple companion binaries are present the right architecture wins.
func platformVariants(name string) []string {
	goos, goarch := runtime.GOOS, runtime.GOARCH
	if goos == "windows" {
		// On Windows, prefer the .exe-suffixed forms.
		base := name
		if filepath.Ext(name) == ".exe" {
			base = name[:len(name)-4]
		}
		return []string{
			base + "-" + goos + "-" + goarch + ".exe",
			base + "-" + goos + ".exe",
			base + ".exe",
			base,
		}
	}
	return []string{
		name + "-" + goos + "-" + goarch,
		name + "-" + goos,
		name,
	}
}

// Find looks for a binary in PATH, then in the current directory,
// then next to the running executable itself.
// On Linux, exec.LookPath does NOT check the current directory, so users placing
// dnstt-client next to the scanner get "not found". This fixes that.
// It also checks platform-specific names (e.g. dnstt-client-linux) so users
// don't need to rename downloaded release files.
func Find(name string) (string, error) {
	variants := platformVariants(name)

	// Check PATH first (all variants)
	for _, v := range variants {
		if p, err := exec.LookPath(v); err == nil {
			return p, nil
		}
	}

	// Check current directory (all variants)
	for _, v := range variants {
		if abs, err := filepath.Abs(v); err == nil {
			if info, err := os.Stat(abs); err == nil {
				if isExecutable(info) {
					return abs, nil
				}
			}
		}
	}

	// Check directory where the running executable is located (all variants)
	if exe, err := os.Executable(); err == nil {
		for _, v := range variants {
			candidate := filepath.Join(filepath.Dir(exe), v)
			if info, err := os.Stat(candidate); err == nil {
				if isExecutable(info) {
					return candidate, nil
				}
			}
		}
	}

	hint := ""
	switch name {
	case "dnstt-client":
		hint = "\n\nDownload pre-built binary from findns releases:\n  https://github.com/SamNet-dev/findns/releases/latest\n\nOr install with Go:\n  go install www.bamsoftware.com/git/dnstt.git/dnstt-client@latest"
	case "slipstream-client":
		hint = "\n\nDownload from: https://github.com/Mygod/slipstream-rust/releases"
	case "masterdnsvpn-client":
		hint = "\n\nDownload pre-bundled MasterDnsVPN client from findns releases:\n  https://github.com/SamNet-dev/findns/releases/latest\n\nFiles are named masterdnsvpn-client-<os>-<arch> and are auto-discovered\nwhen placed next to the findns binary. Upstream source:\n  https://github.com/masterking32/MasterDnsVPN/releases/latest"
	}

	pathHelp := fmt.Sprintf("  2. Move it to a folder in PATH:  sudo mv %s /usr/local/bin/\n  3. Or add current directory to PATH:  export PATH=$PATH:$(pwd)", name)
	if runtime.GOOS == "windows" {
		pathHelp = fmt.Sprintf("  2. Or add the folder to PATH:  set PATH=%%PATH%%;%%cd%%")
	}
	return "", fmt.Errorf("%s not found in PATH, current directory, or next to findns.%s\n\nIf already downloaded, either:\n  1. Place it next to the findns executable\n%s", name, hint, pathHelp)
}
