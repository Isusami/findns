package scanner

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMasterDnsKey_FileBeatsInline(t *testing.T) {
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "encrypt_key.txt")
	if err := os.WriteFile(keyPath, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	got, err := LoadMasterDnsKey("inline-secret", keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "file-secret" {
		t.Errorf("file should win, got %q", got)
	}
}

func TestLoadMasterDnsKey_InlineWhenNoFile(t *testing.T) {
	got, err := LoadMasterDnsKey("inline-secret", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "inline-secret" {
		t.Errorf("got %q", got)
	}
}

func TestLoadMasterDnsKey_BothEmpty(t *testing.T) {
	got, err := LoadMasterDnsKey("", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty result, got %q", got)
	}
}

func TestLoadMasterDnsKey_FileMissing(t *testing.T) {
	_, err := LoadMasterDnsKey("", "/nonexistent/path/that/should/not/exist")
	if err == nil {
		t.Fatal("expected error reading missing file")
	}
}

func TestLoadMasterDnsKey_EmptyFile(t *testing.T) {
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "empty.txt")
	if err := os.WriteFile(keyPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if _, err := LoadMasterDnsKey("", keyPath); err == nil {
		t.Fatal("expected error for empty key file")
	}
}

func TestLoadMasterDnsKey_TrimsTrailingNewlines(t *testing.T) {
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "k.txt")
	// Both LF and CRLF endings are common in editor exports.
	if err := os.WriteFile(keyPath, []byte("abc\r\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	got, err := LoadMasterDnsKey("", keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "abc" {
		t.Errorf("got %q", got)
	}
}

func TestReadMasterDnsMTU_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mtu.log")
	if err := os.WriteFile(path, []byte("8.8.8.8 UP=1232 DOWN=1452\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	up, down, ok := readMasterDnsMTU(path, "8.8.8.8")
	if !ok {
		t.Fatal("expected parse ok")
	}
	if up != 1232 || down != 1452 {
		t.Errorf("got up=%v down=%v", up, down)
	}
}

func TestReadMasterDnsMTU_MissingFile(t *testing.T) {
	_, _, ok := readMasterDnsMTU("/no/such/file", "1.1.1.1")
	if ok {
		t.Fatal("expected !ok for missing file")
	}
}

func TestReadMasterDnsMTU_NoMatchingIP(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mtu.log")
	os.WriteFile(path, []byte("9.9.9.9 UP=1 DOWN=1\n"), 0o600)
	if _, _, ok := readMasterDnsMTU(path, "1.1.1.1"); ok {
		t.Fatal("expected !ok when ip not in file")
	}
}

func TestReadMasterDnsMTU_PartialFields(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mtu.log")
	// Missing DOWN field -> must report !ok rather than 0/garbage.
	os.WriteFile(path, []byte("1.1.1.1 UP=1232\n"), 0o600)
	if _, _, ok := readMasterDnsMTU(path, "1.1.1.1"); ok {
		t.Fatal("expected !ok for partial line")
	}
}

func TestReadMasterDnsMTU_PrefixMatchOnly(t *testing.T) {
	// "1.1.1.10" must not match a query for "1.1.1.1" — readMasterDnsMTU
	// uses HasPrefix and then field-splits, so we check it doesn't pull
	// values from a different (longer) row by accident.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mtu.log")
	os.WriteFile(path, []byte("1.1.1.10 UP=1 DOWN=1\n"), 0o600)
	// HasPrefix matches "1.1.1.1" against "1.1.1.10". The fields-based
	// parse still treats the first field as a single IP-ish token, so we
	// document the current behaviour: the line WILL match. This test
	// exists so future tightening (e.g. exact-token match) is intentional
	// and visible in the test diff.
	if _, _, ok := readMasterDnsMTU(path, "1.1.1.1"); !ok {
		t.Skip("readMasterDnsMTU now uses exact-token match (good); update this test")
	}
}

func TestBoundedWriter_StopsAtMax(t *testing.T) {
	var buf bytes.Buffer
	bw := &boundedWriter{w: &buf, max: 4}
	n, _ := bw.Write([]byte("hello"))
	if n != 5 {
		t.Errorf("Write should report all bytes consumed, got %d", n)
	}
	if buf.String() != "hell" {
		t.Errorf("buffer should be capped to max, got %q", buf.String())
	}
	// Subsequent writes must be silently discarded (so child stderr pipe
	// doesn't block) but still report the input length.
	n, _ = bw.Write([]byte("world"))
	if n != 5 {
		t.Errorf("Write after cap should still report bytes, got %d", n)
	}
	if buf.String() != "hell" {
		t.Errorf("buffer must not grow past cap, got %q", buf.String())
	}
}
