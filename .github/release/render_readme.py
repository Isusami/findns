#!/usr/bin/env python3
"""Render a per-platform README.txt for a findns release zip.

Usage: render_readme.py <os> <arch> <ext> <version> <out>

Called from the release workflow. Kept as a script (not a static file)
so a single source of truth produces every platform's README with the
right binary name, line-continuation syntax, and shell hints.
"""

from __future__ import annotations

import sys
from pathlib import Path


COMMON_TAIL = """\
Auto-detected files
-------------------

If you simply run `findns scan --domain t.example.com --pubkey <hex>` the
scanner will look next to {bin} for:

  scan_ips_public.txt   bundled CIDR list (~6,166 /24 ranges).
                        Used as --cidr-file when no other input source
                        is provided. Defaults to --cidr-sample 10 so the
                        scan is tractable; pass --cidr-sample 0 for the
                        full ~1.57M IPs.

  masterdnsvpn-client{ext}   companion binary used by `findns e2e masterdns`
                        and the masterdns step in the TUI.

  client_config.toml    optional template for the MasterDnsVPN client.
                        The scanner only overrides DOMAINS, ENCRYPTION_KEY,
                        DATA_ENCRYPTION_METHOD, LISTEN_IP, LISTEN_PORT and
                        leaves your other settings alone.

Source / docs / latest releases:
  https://github.com/Isusami/findns
"""


WINDOWS_BODY = """\
findns {version} - DNS tunnel scanner ({os}/{arch})
====================================================

Contents
--------

  findns.exe                Main scanner binary. Run from cmd.exe,
                            PowerShell, or Windows Terminal.
  masterdnsvpn-client.exe   Companion binary for the e2e/masterdns step.
  scan_ips_public.txt       Bundled CIDR list (~6,166 /24 ranges).
                            Auto-detected by `findns scan` when no
                            -i / --cidr / --cidr-file is set.
  README.txt                This file.

Quick start
-----------

  1) Open cmd.exe (Win+R, type cmd, Enter), or open Windows Terminal /
     PowerShell.
  2) cd into the folder you extracted this zip to.
  3) See available commands:

       findns.exe --help

  4) Launch the interactive TUI:

       findns.exe

  5) End-to-end MasterDnsVPN scan against your own resolver list, using
     cmd.exe `^` line continuation:

       findns.exe e2e masterdns ^
         --input scan_ips_public.txt ^
         --output mdvpn_results.json ^
         --masterdns-domain w.example.com ^
         --masterdns-domain w.example2.com ^
         --masterdns-key-file mdkey.txt ^
         --masterdns-encryption-method 2 ^
         --workers 1 ^
         --e2e-timeout 45

     Or as a single line (safest copy/paste):

       findns.exe e2e masterdns --input scan_ips_public.txt --output mdvpn_results.json --masterdns-domain w.example.com --masterdns-domain w.example2.com --masterdns-key-file mdkey.txt --masterdns-encryption-method 2 --workers 1 --e2e-timeout 45

  6) Scan against the bundled global /24 list (auto-detected):

       findns.exe scan --domain t.example.com --pubkey <hex>

Notes
-----

  - Double-clicking findns.exe from File Explorer is supported but not
    the intended workflow. A short message will appear and the window
    will wait for Enter; please use cmd.exe / PowerShell / Windows
    Terminal for the full TUI experience.

  - PowerShell users: prefix the binary with `.\\` and use a backtick `
    instead of `^` for line continuation, e.g. `.\\findns.exe e2e ...`.

"""


UNIX_BODY = """\
findns {version} - DNS tunnel scanner ({os}/{arch})
====================================================

Contents
--------

  findns                   Main scanner binary.
  masterdnsvpn-client      Companion binary for the e2e/masterdns step.
  scan_ips_public.txt      Bundled CIDR list (~6,166 /24 ranges).
                           Auto-detected by `findns scan` when no
                           -i / --cidr / --cidr-file is set.{slipstream_line}
  README.txt               This file.

Quick start
-----------

  1) Open a terminal and cd into the folder you extracted this zip to.
  2) (One-time) make the binaries executable. macOS Gatekeeper may
     also need a one-off allow on first launch:

       chmod +x ./findns ./masterdnsvpn-client{slipstream_chmod}
       # macOS only, if Gatekeeper blocks the binary:
       xattr -d com.apple.quarantine ./findns ./masterdnsvpn-client 2>/dev/null || true

  3) See available commands:

       ./findns --help

  4) Launch the interactive TUI:

       ./findns

  5) End-to-end MasterDnsVPN scan against your own resolver list:

       ./findns e2e masterdns \\
         --input scan_ips_public.txt \\
         --output mdvpn_results.json \\
         --masterdns-domain w.example.com \\
         --masterdns-domain w.example2.com \\
         --masterdns-key-file mdkey.txt \\
         --masterdns-encryption-method 2 \\
         --workers 1 \\
         --e2e-timeout 45

  6) Scan against the bundled global /24 list (auto-detected):

       ./findns scan --domain t.example.com --pubkey <hex>

"""


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        print("usage: render_readme.py <os> <arch> <ext> <version> <out>", file=sys.stderr)
        return 2
    _, os_name, arch, ext, version, out = argv

    is_windows = os_name == "windows"
    is_linux_amd64 = (os_name, arch) == ("linux", "amd64")

    if is_windows:
        body = WINDOWS_BODY.format(version=version, os=os_name, arch=arch)
        bin_label = "findns.exe"
        ext_label = ".exe"
    else:
        slip_line = (
            "\n  slipstream-client        Companion binary for the e2e/slipstream step."
            if is_linux_amd64 else ""
        )
        slip_chmod = " ./slipstream-client" if is_linux_amd64 else ""
        body = UNIX_BODY.format(
            version=version, os=os_name, arch=arch,
            slipstream_line=slip_line, slipstream_chmod=slip_chmod,
        )
        bin_label = "findns"
        ext_label = ""

    tail = COMMON_TAIL.format(bin=bin_label, ext=ext_label)
    Path(out).write_text(body + tail, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
