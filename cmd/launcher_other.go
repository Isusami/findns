//go:build !windows

package main

// wasLaunchedFromExplorer is a no-op on non-Windows platforms: there
// is no equivalent "fresh console spawned by GUI shell" concept on
// macOS/Linux, and the TUI works correctly from a terminal there.
func wasLaunchedFromExplorer() bool { return false }

// showExplorerLaunchHintAndWait is unused on non-Windows; defined only
// so the build-time call in cmd/root.go compiles cleanly.
func showExplorerLaunchHintAndWait() {}
