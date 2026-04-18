//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wasLaunchedFromExplorer reports whether the binary was started by
// double-clicking it in Windows Explorer (or any other GUI shell).
//
// Detection is done via GetConsoleProcessList: when launched from a
// shell like cmd.exe / PowerShell / Windows Terminal, both the parent
// shell and our process are attached to the same console, so the
// returned count is >= 2. When launched from Explorer, Windows spawns
// a fresh console for our process and only we are attached to it, so
// the count is exactly 1. This is the same heuristic used by the
// Python launcher and many native CLIs.
//
// Returns false on any API failure to avoid breaking legitimate
// console launches.
func wasLaunchedFromExplorer() bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getConsoleProcessList := kernel32.NewProc("GetConsoleProcessList")
	if err := getConsoleProcessList.Find(); err != nil {
		return false
	}
	var pids [4]uint32
	r1, _, _ := getConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)),
	)
	count := uint32(r1)
	return count == 1
}

// showExplorerLaunchHintAndWait prints the short, friendly "open cmd
// and run it from there" message and blocks until the user presses
// Enter, so the auto-spawned console window stays visible long enough
// to read the message instead of flashing and closing.
func showExplorerLaunchHintAndWait() {
	fmt.Println("This is a command line tool.")
	fmt.Println("You need to open cmd.exe and run it from there.")
	fmt.Println()
	fmt.Println("Quick start:")
	fmt.Println("  1) Press Win+R, type cmd, press Enter")
	fmt.Println("  2) cd to the folder containing findns.exe")
	fmt.Println("  3) Run:  findns.exe --help")
	fmt.Println()
	fmt.Print("Press Enter to close this window...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
