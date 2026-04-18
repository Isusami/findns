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
	// must compare the first whitespace-token for exact equality, not use
	// HasPrefix on the full line (which would silently misattribute MTU).
	tmp := t.TempDir()
	path := filepath.Join(tmp, "mtu.log")
	os.WriteFile(path, []byte("1.1.1.10 UP=1 DOWN=1\n"), 0o600)
	if _, _, ok := readMasterDnsMTU(path, "1.1.1.1"); ok {
		t.Fatal("expected !ok — '1.1.1.1' must not match a row whose first token is '1.1.1.10'")
	}
}

// Bug 1 reproduction: covers H1/H2/H3 from the debug session. Each subtest
// queries a short IP against an MTU file containing a longer prefix-collision
// IP. All three currently FAIL with the buggy strings.HasPrefix(line, ip)
// implementation and pass once the parser switches to fields[0] == ip.
func TestReadMasterDnsMTU_BugRepro_PrefixCollision(t *testing.T) {
	cases := []struct {
		name     string
		query    string
		fileBody string
		// wantOK = expected ok return; for these scenarios we want false
		// (the queried IP genuinely isn't in the file).
	}{
		{
			name:     "H1_only_longer_ip_in_file",
			query:    "1.1.1.1",
			fileBody: "1.1.1.10 UP=999 DOWN=888\n",
		},
		{
			name:     "H2_longer_ip_first_no_exact_match",
			query:    "1.1.1.1",
			fileBody: "1.1.1.10 UP=999 DOWN=888\n1.1.1.100 UP=777 DOWN=666\n",
		},
		{
			name:     "H3_different_subnet_collision",
			query:    "10.0.0.1",
			fileBody: "10.0.0.10 UP=42 DOWN=24\n",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			path := filepath.Join(tmp, "mtu.log")
			if err := os.WriteFile(path, []byte(tc.fileBody), 0o600); err != nil {
				t.Fatal(err)
			}
			up, down, ok := readMasterDnsMTU(path, tc.query)
			if ok {
				t.Fatalf("BUG: query=%q matched non-equal first token; got up=%v down=%v ok=true (want ok=false)",
					tc.query, up, down)
			}
		})
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
