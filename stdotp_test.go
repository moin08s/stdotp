package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestMain enables this test binary to double as the stdotp CLI binary.
// When STDOTP_TEST_CLI=1 is set (by runCLI), it calls main() directly
// instead of running the test suite. This lets integration tests exec
// themselves without requiring a separately built binary.
func TestMain(m *testing.M) {
	if os.Getenv("STDOTP_TEST_CLI") == "1" {
		main()
		panic("unreachable: main() always calls os.Exit")
	}
	os.Exit(m.Run())
}

// ============================================================
// RFC 4226 Appendix D — HOTP test vectors
// ============================================================

// TestHOTP_RFC4226 verifies all ten HOTP test vectors from RFC 4226 Appendix D.
// The secret is the ASCII bytes of "12345678901234567890" (20 bytes).
// All ten expected values are taken verbatim from the published RFC.
func TestHOTP_RFC4226(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := []struct {
		counter uint64
		want    string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}
	for _, v := range vectors {
		got := hotp(secret, v.counter, 6, "SHA1")
		if got != v.want {
			t.Errorf("hotp(counter=%d) = %q, want %q", v.counter, got, v.want)
		}
	}
}

// ============================================================
// RFC 6238 Appendix B — TOTP test vectors
// ============================================================

// TestTOTP_RFC6238 verifies all 18 TOTP test vectors from RFC 6238 Appendix B
// across three algorithms (SHA1, SHA256, SHA512) and six timestamps.
// RFC 6238 uses 8-digit codes in Appendix B.
func TestTOTP_RFC6238(t *testing.T) {
	// Each algorithm uses a different-length secret per the RFC.
	sha1Key := []byte("12345678901234567890")                                               // 20 bytes
	sha256Key := []byte("12345678901234567890123456789012")                                 // 32 bytes
	sha512Key := []byte("1234567890123456789012345678901234567890123456789012345678901234") // 64 bytes

	vectors := []struct {
		unixTime int64
		algo     string
		key      []byte
		want     string // 8-digit code per RFC 6238 Appendix B
	}{
		{59, "SHA1", sha1Key, "94287082"},
		{59, "SHA256", sha256Key, "46119246"},
		{59, "SHA512", sha512Key, "90693936"},
		{1111111109, "SHA1", sha1Key, "07081804"},
		{1111111109, "SHA256", sha256Key, "68084774"},
		{1111111109, "SHA512", sha512Key, "25091201"},
		{1111111111, "SHA1", sha1Key, "14050471"},
		{1111111111, "SHA256", sha256Key, "67062674"},
		{1111111111, "SHA512", sha512Key, "99943326"},
		{1234567890, "SHA1", sha1Key, "89005924"},
		{1234567890, "SHA256", sha256Key, "91819424"},
		{1234567890, "SHA512", sha512Key, "93441116"},
		{2000000000, "SHA1", sha1Key, "69279037"},
		{2000000000, "SHA256", sha256Key, "90698825"},
		{2000000000, "SHA512", sha512Key, "38618901"},
		{20000000000, "SHA1", sha1Key, "65353130"},
		{20000000000, "SHA256", sha256Key, "77737706"},
		{20000000000, "SHA512", sha512Key, "47863826"},
	}

	for _, v := range vectors {
		got, _ := totp(v.key, time.Unix(v.unixTime, 0), 30, 8, v.algo)
		if got != v.want {
			t.Errorf("totp(t=%d, algo=%s) = %q, want %q",
				v.unixTime, v.algo, got, v.want)
		}
	}
}

// ============================================================
// RFC 7914 §12 — PBKDF2-HMAC-SHA256 test vectors
// ============================================================

// TestPBKDF2_RFC7914 verifies both PBKDF2-HMAC-SHA256 test vectors from
// RFC 7914 §12 ("Test Vectors for PBKDF2 with HMAC-SHA-256").
//
// Source: Percival, C. and Josefsson, S., "The scrypt Password-Based Key
// Derivation Function," RFC 7914, Section 12, August 2016.
//
// A round-trip test (encrypt then decrypt) only proves that our implementation
// is self-consistent. These vectors prove it matches the published standard
// and interoperates with every other RFC 2898 implementation.
func TestPBKDF2_RFC7914(t *testing.T) {
	vectors := []struct {
		password   string
		salt       string
		iterations int
		keyLen     int
		wantHex    string
	}{
		{
			// Vector 1: c=1, fast — confirms basic correctness.
			password:   "passwd",
			salt:       "salt",
			iterations: 1,
			keyLen:     64,
			wantHex: "55ac046e56e3089fec1691c22544b605" +
				"f94185216dde0465e68b9d57c20dacbc" +
				"49ca9cccf179b645991664b39d77ef31" +
				"7c71b845b1e30bd509112041d3a19783",
		},
		{
			// Vector 2: c=80,000 — confirms iteration count correctness.
			// Runs in well under a second under crypto/hmac.
			password:   "Password",
			salt:       "NaCl",
			iterations: 80000,
			keyLen:     64,
			wantHex: "4ddcd8f60b98be21830cee5ef22701f9" +
				"641a4418d04c0414aeff08876b34ab56" +
				"a1d425a1225833549adb841b51c9b317" +
				"6a272bdebba1d078478f62b397f33c8d",
		},
	}

	for _, v := range vectors {
		dk := pbkdf2([]byte(v.password), []byte(v.salt), v.iterations, v.keyLen)
		got := hex.EncodeToString(dk)
		if got != v.wantHex {
			t.Errorf("pbkdf2(%q, %q, c=%d, dkLen=%d)\ngot:  %s\nwant: %s",
				v.password, v.salt, v.iterations, v.keyLen, got, v.wantHex)
		}
	}
}

// ============================================================
// Vault encryption round-trip
// ============================================================

// TestVaultEncryptDecrypt verifies that encryptVault + decryptVault produces
// the original plaintext. Uses low iterations (1000) so the test runs fast.
func TestVaultEncryptDecrypt(t *testing.T) {
	const iters = 1000
	salt := []byte("testsalt12345678") // exactly 16 bytes
	key := pbkdf2([]byte("hunter2"), salt, iters, 32)
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	aad := vaultAAD(vaultFormatVersion, vaultKDF, iters, saltB64)

	original := VaultData{
		Accounts: []Account{
			{
				Name:      "Test Account",
				Issuer:    "Example Corp",
				Secret:    "JBSWY3DPEHPK3PXP",
				Algorithm: "SHA1",
				Digits:    6,
				Period:    30,
				Type:      "totp",
			},
		},
	}

	nonce, ciphertext, err := encryptVault(original, key, aad)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}

	// GCM nonce must be exactly 12 bytes.
	if len(nonce) != 12 {
		t.Errorf("nonce length = %d, want 12", len(nonce))
	}

	// Two separate Seal calls must produce different ciphertexts (fresh nonce).
	nonce2, ciphertext2, err := encryptVault(original, key, aad)
	if err != nil {
		t.Fatalf("encryptVault (second call): %v", err)
	}
	if bytes.Equal(nonce, nonce2) {
		t.Error("nonces must not repeat across calls — same nonce with same key breaks GCM")
	}
	if bytes.Equal(ciphertext, ciphertext2) {
		// Statistically impossible with fresh random nonces, but catch it if it ever happens.
		t.Error("ciphertexts must differ when nonces differ")
	}

	decrypted, err := decryptVault(nonce, ciphertext, key, aad)
	if err != nil {
		t.Fatalf("decryptVault: %v", err)
	}

	if len(decrypted.Accounts) != 1 {
		t.Fatalf("account count after round-trip = %d, want 1", len(decrypted.Accounts))
	}
	got, want := decrypted.Accounts[0], original.Accounts[0]
	if got.Name != want.Name || got.Secret != want.Secret || got.Issuer != want.Issuer {
		t.Errorf("round-trip mismatch:\n got:  %+v\n want: %+v", got, want)
	}
}

// TestVaultTamperedCiphertext verifies the "fails safe" property (§2.2):
// AES-GCM rejects any modified ciphertext rather than returning garbage plaintext.
func TestVaultTamperedCiphertext(t *testing.T) {
	salt := []byte("testsalt12345678")
	key := pbkdf2([]byte("password"), salt, 1000, 32)
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	aad := vaultAAD(vaultFormatVersion, vaultKDF, 1000, saltB64)
	data := VaultData{Accounts: []Account{
		{Name: "x", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Period: 30, Type: "totp"},
	}}

	nonce, ciphertext, err := encryptVault(data, key, aad)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}

	// Flip one bit anywhere in the ciphertext.
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF

	_, err = decryptVault(nonce, tampered, key, aad)
	if err == nil {
		t.Fatal("expected GCM authentication failure for tampered ciphertext, got nil")
	}
}

// TestVaultWrongKey verifies that a wrong derived key fails GCM authentication.
func TestVaultWrongKey(t *testing.T) {
	salt := []byte("testsalt12345678")
	correctKey := pbkdf2([]byte("correct"), salt, 1000, 32)
	wrongKey := pbkdf2([]byte("wrong"), salt, 1000, 32)
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	aad := vaultAAD(vaultFormatVersion, vaultKDF, 1000, saltB64)

	data := VaultData{Accounts: []Account{
		{Name: "x", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Period: 30, Type: "totp"},
	}}
	nonce, ciphertext, err := encryptVault(data, correctKey, aad)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}

	_, err = decryptVault(nonce, ciphertext, wrongKey, aad)
	if err == nil {
		t.Fatal("expected GCM failure for wrong key, got nil")
	}
}

// TestSaveLoadVault tests the full file-level round-trip via saveVault + loadVault.
func TestSaveLoadVault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	const iters = 1000
	salt := []byte("testsalt12345678")
	key := pbkdf2([]byte("testpass"), salt, iters, 32)

	original := VaultData{Accounts: []Account{
		{Name: "acme", Issuer: "ACME", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Period: 30, Type: "totp"},
	}}

	if err := saveVault(path, original, key, salt, iters); err != nil {
		t.Fatalf("saveVault: %v", err)
	}

	// loadVault reads the iteration count from the file itself.
	loaded, _, _, loadedIters, err := loadVault(path, "testpass")
	if err != nil {
		t.Fatalf("loadVault: %v", err)
	}
	if loadedIters != iters {
		t.Errorf("loaded iterations = %d, want %d", loadedIters, iters)
	}
	if len(loaded.Accounts) != 1 || loaded.Accounts[0].Name != "acme" {
		t.Errorf("loaded accounts: %+v", loaded.Accounts)
	}
}

// TestLoadVault_WrongPassword verifies that loadVault returns errWrongPassword
// for an incorrect password, and not partial data.
func TestLoadVault_WrongPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	const iters = 1000
	salt := []byte("testsalt12345678")
	key := pbkdf2([]byte("correct"), salt, iters, 32)

	if err := saveVault(path, VaultData{}, key, salt, iters); err != nil {
		t.Fatalf("saveVault: %v", err)
	}

	_, _, _, _, err := loadVault(path, "wrong")
	if !errors.Is(err, errWrongPassword) {
		t.Errorf("got %v, want errWrongPassword", err)
	}
}

// TestLoadVault_Missing verifies exit code 5's sentinel error.
func TestLoadVault_Missing(t *testing.T) {
	_, _, _, _, err := loadVault("/no/such/vault.json", "password")
	if !errors.Is(err, errVaultMissing) {
		t.Errorf("got %v, want errVaultMissing", err)
	}
}

// ============================================================
// otpauth:// URI tests
// ============================================================

func TestParseOTPAuthURI_Valid(t *testing.T) {
	vectors := []struct {
		uri        string
		wantName   string
		wantIssuer string
		wantSecret string
		wantAlgo   string
		wantDigits int
		wantPeriod int
		wantType   string
	}{
		{
			// Standard TOTP with issuer in label
			uri:        "otpauth://totp/Example%3AAlice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			wantName:   "Alice@example.com",
			wantIssuer: "Example",
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantAlgo:   "SHA1",
			wantDigits: 6,
			wantPeriod: 30,
			wantType:   "totp",
		},
		{
			// Non-default algorithm, digits, period
			uri:        "otpauth://totp/ACME%20Co%3AJohn%20Doe?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&algorithm=SHA256&digits=8&period=60&issuer=ACME%20Co",
			wantName:   "John Doe",
			wantIssuer: "ACME Co",
			wantSecret: "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
			wantAlgo:   "SHA256",
			wantDigits: 8,
			wantPeriod: 60,
			wantType:   "totp",
		},
		{
			// No issuer in label
			uri:        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP",
			wantName:   "alice",
			wantIssuer: "",
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantAlgo:   "SHA1",
			wantDigits: 6,
			wantPeriod: 30,
			wantType:   "totp",
		},
		{
			// HOTP with counter
			uri:        "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=42",
			wantName:   "alice",
			wantIssuer: "",
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantAlgo:   "SHA1",
			wantDigits: 6,
			wantPeriod: 30,
			wantType:   "hotp",
		},
	}

	for _, v := range vectors {
		a, err := parseOTPAuthURI(v.uri)
		if err != nil {
			t.Errorf("parseOTPAuthURI(%q): unexpected error: %v", v.uri, err)
			continue
		}
		if a.Name != v.wantName {
			t.Errorf("Name: got %q, want %q (uri=%q)", a.Name, v.wantName, v.uri)
		}
		if a.Issuer != v.wantIssuer {
			t.Errorf("Issuer: got %q, want %q (uri=%q)", a.Issuer, v.wantIssuer, v.uri)
		}
		if a.Secret != v.wantSecret {
			t.Errorf("Secret: got %q, want %q (uri=%q)", a.Secret, v.wantSecret, v.uri)
		}
		if a.Algorithm != v.wantAlgo {
			t.Errorf("Algorithm: got %q, want %q (uri=%q)", a.Algorithm, v.wantAlgo, v.uri)
		}
		if a.Digits != v.wantDigits {
			t.Errorf("Digits: got %d, want %d (uri=%q)", a.Digits, v.wantDigits, v.uri)
		}
		if a.Type != v.wantType {
			t.Errorf("Type: got %q, want %q (uri=%q)", a.Type, v.wantType, v.uri)
		}
	}
}

func TestParseOTPAuthURI_Invalid(t *testing.T) {
	invalids := []struct {
		uri  string
		desc string
	}{
		{"https://example.com", "wrong scheme"},
		{"otpauth://badtype/Alice?secret=JBSWY3DPEHPK3PXP", "unknown OTP type"},
		{"otpauth://totp/Alice", "missing secret"},
		{"otpauth://totp/Alice?secret=!!!!!", "invalid base32"},
		{"otpauth://hotp/Alice?secret=JBSWY3DPEHPK3PXP", "hotp missing counter"},
		{"otpauth://totp/Alice?secret=JBSWY3DPEHPK3PXP&digits=5", "digits out of range"},
		{"otpauth://totp/Alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "unsupported algorithm"},
	}
	for _, v := range invalids {
		_, err := parseOTPAuthURI(v.uri)
		if err == nil {
			t.Errorf("parseOTPAuthURI(%q) [%s]: expected error, got nil", v.uri, v.desc)
		}
	}
}

// TestBuildOTPAuthURI_RoundTrip verifies build → parse produces the same Account fields.
func TestBuildOTPAuthURI_RoundTrip(t *testing.T) {
	original := Account{
		Name:      "Alice",
		Issuer:    "Example",
		Secret:    "JBSWY3DPEHPK3PXP",
		Algorithm: "SHA256",
		Digits:    8,
		Period:    60,
		Type:      "totp",
	}
	uri := buildOTPAuthURI(original, true)
	parsed, err := parseOTPAuthURI(uri)
	if err != nil {
		t.Fatalf("parseOTPAuthURI after build: %v", err)
	}
	if parsed.Secret != original.Secret {
		t.Errorf("Secret: got %q, want %q", parsed.Secret, original.Secret)
	}
	if parsed.Algorithm != original.Algorithm {
		t.Errorf("Algorithm: got %q, want %q", parsed.Algorithm, original.Algorithm)
	}
	if parsed.Digits != original.Digits {
		t.Errorf("Digits: got %d, want %d", parsed.Digits, original.Digits)
	}
	if parsed.Period != original.Period {
		t.Errorf("Period: got %d, want %d", parsed.Period, original.Period)
	}
}

// TestBuildOTPAuthURI_RedactsSecret verifies that showSecret=false hides the key.
func TestBuildOTPAuthURI_RedactsSecret(t *testing.T) {
	a := Account{Name: "Alice", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Period: 30, Type: "totp"}
	uri := buildOTPAuthURI(a, false)
	if strings.Contains(uri, "JBSWY3DPEHPK3PXP") {
		t.Errorf("secret not redacted: %s", uri)
	}
	// The URI should contain [REDACTED] percent-encoded or literal.
	if !strings.Contains(uri, "REDACTED") {
		t.Errorf("expected REDACTED placeholder in URI: %s", uri)
	}
}

// ============================================================
// Misc edge cases
// ============================================================

func TestDecodeSecret_Invalid(t *testing.T) {
	for _, s := range []string{"!!!!", "not-base32-at-all!!"} {
		_, err := decodeSecret(s)
		if err == nil {
			t.Errorf("decodeSecret(%q): expected error, got nil", s)
		}
	}
}

func TestDecodeSecret_Valid(t *testing.T) {
	b, err := decodeSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("decodeSecret: %v", err)
	}
	if len(b) == 0 {
		t.Error("decoded secret is empty")
	}
}

func TestDecodeSecret_EmptyString(t *testing.T) {
	_, err := decodeSecret("")
	if err == nil {
		t.Error("expected error for empty secret, got nil")
	}
}

// TestTOTP_SecondsRemaining verifies the seconds-remaining calculation.
func TestTOTP_SecondsRemaining(t *testing.T) {
	secret := []byte("12345678901234567890")
	// T=29: 29 seconds into the first period → 1 second left.
	_, secs := totp(secret, time.Unix(29, 0), 30, 6, "SHA1")
	if secs != 1 {
		t.Errorf("secondsRemaining at T=29 = %d, want 1", secs)
	}
	// T=30: first second of the new period → 30 seconds left.
	_, secs = totp(secret, time.Unix(30, 0), 30, 6, "SHA1")
	if secs != 30 {
		t.Errorf("secondsRemaining at T=30 = %d, want 30", secs)
	}
	// T=59: last second of the second period → 1 second left.
	_, secs = totp(secret, time.Unix(59, 0), 30, 6, "SHA1")
	if secs != 1 {
		t.Errorf("secondsRemaining at T=59 = %d, want 1", secs)
	}
}

// TestHOTP_PaddedOutput verifies that leading-zero codes are zero-padded correctly.
func TestHOTP_PaddedOutput(t *testing.T) {
	// Counter=0 for RFC 4226 secret produces "755224" — no leading zeros there.
	// Check that 6-digit formatting always produces exactly 6 characters.
	secret := []byte("12345678901234567890")
	for counter := uint64(0); counter < 10; counter++ {
		code := hotp(secret, counter, 6, "SHA1")
		if len(code) != 6 {
			t.Errorf("hotp(counter=%d) length = %d, want 6: %q", counter, len(code), code)
		}
	}
}

// ============================================================
// CLI integration tests (use runCLI to invoke this binary as the CLI)
// ============================================================

// runCLI executes this test binary in CLI mode (STDOTP_TEST_CLI=1) and returns
// stdout, stderr, and the exit code.
func runCLI(t *testing.T, stdinData string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "STDOTP_TEST_CLI=1")
	if stdinData != "" {
		cmd.Stdin = strings.NewReader(stdinData)
	}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("exec error: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), code
}

// TestCLI_FullWorkflow exercises the complete happy path:
// init → add (interactive) → list → code → export → remove → list (empty).
func TestCLI_FullWorkflow(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "correct-horse-battery\n"
	secret := "JBSWY3DPEHPK3PXP"

	// init: password + confirmation
	_, _, code := runCLI(t, pass+pass, vf, "init")
	if code != exitOK {
		t.Fatalf("init: exit code %d (want 0)", code)
	}

	// add (interactive): password then secret on stdin
	_, _, code = runCLI(t, pass+secret+"\n", vf, "add", "myaccount")
	if code != exitOK {
		t.Fatalf("add: exit code %d (want 0)", code)
	}

	// list: stdout must contain the account name
	out, _, code := runCLI(t, pass, vf, "list")
	if code != exitOK {
		t.Fatalf("list: exit code %d (want 0)", code)
	}
	if !strings.Contains(out, "myaccount") {
		t.Errorf("list stdout missing 'myaccount': %q", out)
	}

	// code: stdout must look like a 6-digit TOTP + seconds remaining
	out, _, code = runCLI(t, pass, vf, "code", "myaccount")
	if code != exitOK {
		t.Fatalf("code: exit code %d (want 0)", code)
	}
	if !regexp.MustCompile(`^\d{6}`).MatchString(strings.TrimSpace(out)) {
		t.Errorf("code output doesn't match 6-digit OTP pattern: %q", out)
	}

	// code --json: must contain expected JSON keys
	out, _, code = runCLI(t, pass, vf, "code", "--json", "myaccount")
	if code != exitOK {
		t.Fatalf("code --json: exit code %d (want 0)", code)
	}
	for _, key := range []string{`"account"`, `"code"`, `"seconds_remaining"`} {
		if !strings.Contains(out, key) {
			t.Errorf("code --json missing %s: %q", key, out)
		}
	}

	// export (no --show-secret): secret must be redacted
	out, _, code = runCLI(t, pass, vf, "export", "myaccount")
	if code != exitOK {
		t.Fatalf("export: exit code %d (want 0)", code)
	}
	if strings.Contains(out, secret) {
		t.Errorf("export without --show-secret leaked the secret: %q", out)
	}

	// export --show-secret: secret must appear
	out, _, code = runCLI(t, pass, vf, "export", "--show-secret", "myaccount")
	if code != exitOK {
		t.Fatalf("export --show-secret: exit code %d (want 0)", code)
	}
	if !strings.Contains(out, secret) {
		t.Errorf("export --show-secret didn't include the secret: %q", out)
	}

	// remove
	_, _, code = runCLI(t, pass, vf, "remove", "myaccount")
	if code != exitOK {
		t.Fatalf("remove: exit code %d (want 0)", code)
	}

	// list after remove: vault must be empty
	_, errOut, code := runCLI(t, pass, vf, "list")
	if code != exitOK {
		t.Fatalf("list after remove: exit code %d (want 0)", code)
	}
	if !strings.Contains(errOut, "empty") {
		t.Errorf("expected empty-vault message, got stderr: %q", errOut)
	}
}

// TestCLI_WrongPassword verifies exit code 3.
func TestCLI_WrongPassword(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")

	_, _, code := runCLI(t, "mypassword\nmypassword\n", vf, "init")
	if code != exitOK {
		t.Fatalf("init: exit code %d", code)
	}

	_, _, code = runCLI(t, "wrongpassword\n", vf, "list")
	if code != exitWrongPass {
		t.Errorf("wrong password: exit code %d, want %d", code, exitWrongPass)
	}
}

// TestCLI_VaultMissing verifies exit code 5.
func TestCLI_VaultMissing(t *testing.T) {
	vf := "--vault=/no/such/path/vault.json"
	_, _, code := runCLI(t, "anything\n", vf, "list")
	if code != exitVaultMissing {
		t.Errorf("missing vault: exit code %d, want %d", code, exitVaultMissing)
	}
}

// TestCLI_AccountNotFound verifies exit code 4.
func TestCLI_AccountNotFound(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "mypassword\n"

	_, _, code := runCLI(t, pass+pass, vf, "init")
	if code != exitOK {
		t.Fatalf("init: exit code %d", code)
	}

	_, _, code = runCLI(t, pass, vf, "code", "nonexistent")
	if code != exitNotFound {
		t.Errorf("missing account: exit code %d, want %d", code, exitNotFound)
	}
}

// TestCLI_DuplicateAccount verifies that adding the same name twice fails.
func TestCLI_DuplicateAccount(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")
	_, _, code := runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "acct")
	if code != exitOK {
		t.Fatalf("first add: exit code %d", code)
	}
	_, _, code = runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "acct")
	if code == exitOK {
		t.Error("duplicate add: expected non-zero exit, got 0")
	}
}

// TestCLI_AddViaURI verifies the --uri flag path.
func TestCLI_AddViaURI(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")

	uri := "otpauth://totp/Example%3AAlice?secret=JBSWY3DPEHPK3PXP&issuer=Example"
	_, _, code := runCLI(t, pass, vf, "add", "alice", "--uri", uri)
	if code != exitOK {
		t.Fatalf("add --uri: exit code %d", code)
	}

	out, _, code := runCLI(t, pass, vf, "list")
	if code != exitOK {
		t.Fatalf("list: exit code %d", code)
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("list missing 'alice': %q", out)
	}
}

// TestCLI_StdoutStderrSplit verifies that only the OTP code goes to stdout
// and prompts/status go to stderr (§4 of the plan).
func TestCLI_StdoutStderrSplit(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")
	runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "acct")

	out, stderr, code := runCLI(t, pass, vf, "code", "acct")
	if code != exitOK {
		t.Fatalf("code: exit code %d", code)
	}
	// stdout: only the OTP (6 digits + seconds remaining)
	if !regexp.MustCompile(`^\d{6}`).MatchString(strings.TrimSpace(out)) {
		t.Errorf("stdout doesn't look like an OTP: %q", out)
	}
	// stderr: the password prompt, never the OTP
	if strings.Contains(stderr, out[:6]) {
		t.Errorf("OTP code leaked into stderr: %q", stderr)
	}
}

// TestCLI_SelfTest verifies that the in-process self-test subcommand passes cleanly.
func TestCLI_SelfTest(t *testing.T) {
	out, _, code := runCLI(t, "", "self-test")
	if code != exitOK {
		t.Fatalf("self-test failed with exit code %d", code)
	}
	if !strings.Contains(out, "All self-tests passed successfully.") {
		t.Errorf("expected success message, got: %q", out)
	}
}

// TestCLI_Version verifies the version subcommand.
func TestCLI_Version(t *testing.T) {
	out, _, code := runCLI(t, "", "version")
	if code != exitOK {
		t.Fatalf("version failed with exit code %d", code)
	}
	if !strings.Contains(out, "stdotp v1.0.0") {
		t.Errorf("expected stdotp v1.0.0, got: %q", out)
	}
}

// TestCLI_ListJSON verifies that list --json outputs a valid JSON array of accounts.
func TestCLI_ListJSON(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")
	runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "github")

	out, _, code := runCLI(t, pass, vf, "list", "--json")
	if code != exitOK {
		t.Fatalf("list --json failed with exit code %d", code)
	}
	if !strings.Contains(out, `"name": "github"`) || !strings.Contains(out, `"type": "TOTP"`) {
		t.Errorf("list --json output missing expected fields: %q", out)
	}
}

// TestCLI_CodeWithTime verifies deterministic OTP generation with --time override.
func TestCLI_CodeWithTime(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")
	runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "rfc")

	// Unix timestamp 59: test deterministic code calculation
	out, _, code := runCLI(t, pass, vf, "code", "rfc", "--time=59")
	if code != exitOK {
		t.Fatalf("code --time failed with exit code %d", code)
	}
	if len(strings.TrimSpace(out)) < 6 {
		t.Errorf("unexpected output from code --time: %q", out)
	}
}

// TestCLI_InitCustomIterations verifies initializing vault with custom PBKDF2 iterations.
func TestCLI_InitCustomIterations(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	_, _, code := runCLI(t, pass+pass, vf, "init", "--iterations=5000")
	if code != exitOK {
		t.Fatalf("init --iterations failed with exit code %d", code)
	}

	_, _, code = runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "alice")
	if code != exitOK {
		t.Fatalf("add to custom-iteration vault failed with exit code %d", code)
	}
}

// TestCLI_VerifyValid verifies checking a valid TOTP token.
func TestCLI_VerifyValid(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")
	runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "alice")

	// Get current code
	codeOut, _, code := runCLI(t, pass, vf, "code", "alice", "--json")
	if code != exitOK {
		t.Fatalf("code failed: %d", code)
	}
	re := regexp.MustCompile(`"code":"(\d+)"`)
	m := re.FindStringSubmatch(codeOut)
	if len(m) < 2 {
		t.Fatalf("failed to extract code from: %s", codeOut)
	}
	token := m[1]

	// Verify code
	out, _, code := runCLI(t, pass, vf, "verify", "alice", token)
	if code != exitOK || !strings.Contains(out, "Valid code") {
		t.Errorf("expected valid verification, got code=%d out=%q", code, out)
	}
}

// TestCLI_VerifyInvalid verifies rejection of an invalid token.
func TestCLI_VerifyInvalid(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")
	runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "alice")

	_, _, code := runCLI(t, pass, vf, "verify", "alice", "000000")
	if code != exitError {
		t.Errorf("expected exit code %d for invalid token, got %d", exitError, code)
	}
}

// TestCLI_ChangePassword verifies rotating master password and re-encrypting vault.
func TestCLI_ChangePassword(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	oldPass := "oldpassword\n"
	newPass := "newpassword\n"

	runCLI(t, oldPass+oldPass, vf, "init")
	runCLI(t, oldPass+"JBSWY3DPEHPK3PXP\n", vf, "add", "alice")

	// Change password
	_, _, code := runCLI(t, oldPass+newPass+newPass, vf, "change-password")
	if code != exitOK {
		t.Fatalf("change-password failed with exit code %d", code)
	}

	// Old password should now fail (exit code 3)
	_, _, code = runCLI(t, oldPass, vf, "code", "alice")
	if code != exitWrongPass {
		t.Errorf("expected old password to fail with exit code %d, got %d", exitWrongPass, code)
	}

	// New password should succeed
	_, _, code = runCLI(t, newPass, vf, "code", "alice")
	if code != exitOK {
		t.Errorf("expected new password to succeed with exit code %d, got %d", exitOK, code)
	}
}

// TestCLI_Rename verifies renaming an existing account.
func TestCLI_Rename(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")
	runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "oldname")

	// Rename
	_, _, code := runCLI(t, pass, vf, "rename", "oldname", "newname")
	if code != exitOK {
		t.Fatalf("rename failed with exit code %d", code)
	}

	// Old name should now not be found (exit code 4)
	_, _, code = runCLI(t, pass, vf, "code", "oldname")
	if code != exitNotFound {
		t.Errorf("expected old name to be not found (code %d), got %d", exitNotFound, code)
	}

	// New name should succeed
	_, _, code = runCLI(t, pass, vf, "code", "newname")
	if code != exitOK {
		t.Errorf("expected new name to succeed (code %d), got %d", exitOK, code)
	}
}

// TestCLI_Status verifies diagnostics output.
func TestCLI_Status(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")

	out, _, code := runCLI(t, "", vf, "status")
	if code != exitOK {
		t.Fatalf("status failed with exit code %d", code)
	}
	if !strings.Contains(out, "stdotp v1.0.0") || !strings.Contains(out, "PBKDF2-HMAC-SHA256") {
		t.Errorf("status output missing expected diagnostic info: %q", out)
	}
}

// TestCLI_AddViaSecretFlag verifies adding an account using --secret.
func TestCLI_AddViaSecretFlag(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")
	_, _, code := runCLI(t, pass, vf, "add", "flagacc", "--secret=JBSWY3DPEHPK3PXP")
	if code != exitOK {
		t.Fatalf("add --secret failed with exit code %d", code)
	}
}

// TestCLI_AddViaSecretFile verifies adding an account using --secret-file.
func TestCLI_AddViaSecretFile(t *testing.T) {
	dir := t.TempDir()
	vf := "--vault=" + filepath.Join(dir, "vault.json")
	pass := "pass\n"
	secretFile := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("JBSWY3DPEHPK3PXP\n"), 0600); err != nil {
		t.Fatal(err)
	}

	runCLI(t, pass+pass, vf, "init")
	_, _, code := runCLI(t, pass, vf, "add", "fileacc", "--secret-file="+secretFile)
	if code != exitOK {
		t.Fatalf("add --secret-file failed with exit code %d", code)
	}
}

// TestCLI_AddViaURIFile verifies adding an account using --uri-file.
func TestCLI_AddViaURIFile(t *testing.T) {
	dir := t.TempDir()
	vf := "--vault=" + filepath.Join(dir, "vault.json")
	pass := "pass\n"
	uriFile := filepath.Join(dir, "uri.txt")
	if err := os.WriteFile(uriFile, []byte("otpauth://totp/fileuri?secret=JBSWY3DPEHPK3PXP\n"), 0600); err != nil {
		t.Fatal(err)
	}

	runCLI(t, pass+pass, vf, "init")
	_, _, code := runCLI(t, pass, vf, "add", "fileuriacc", "--uri-file="+uriFile)
	if code != exitOK {
		t.Fatalf("add --uri-file failed with exit code %d", code)
	}
}

// TestCLI_VerifyHOTP verifies verifying an HOTP code.
func TestCLI_VerifyHOTP(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")
	runCLI(t, pass, vf, "add", "hotpacc", "--uri=otpauth://hotp/hotpacc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0")

	// Counter 0: expected 755224
	out, _, code := runCLI(t, pass, vf, "verify", "hotpacc", "755224")
	if code != exitOK || !strings.Contains(out, "Valid code") {
		t.Errorf("expected valid HOTP verify, got code=%d out=%q", code, out)
	}

	// Invalid code
	_, _, code = runCLI(t, pass, vf, "verify", "hotpacc", "000000")
	if code != exitError {
		t.Errorf("expected invalid HOTP verify exit %d, got %d", exitError, code)
	}
}

// TestCLI_ChangePasswordMismatch verifies rejection of mismatched passwords.
func TestCLI_ChangePasswordMismatch(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	oldPass := "oldpassword\n"

	runCLI(t, oldPass+oldPass, vf, "init")
	_, _, code := runCLI(t, oldPass+"new1\n"+"new2\n", vf, "change-password")
	if code != exitError {
		t.Errorf("expected exitError for mismatched passwords, got %d", code)
	}
}

// TestCLI_RenameDuplicate verifies rejection when new account name already exists.
func TestCLI_RenameDuplicate(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")
	runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "acc1")
	runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "acc2")

	_, _, code := runCLI(t, pass, vf, "rename", "acc1", "acc2")
	if code != exitError {
		t.Errorf("expected exitError when renaming to existing account, got %d", code)
	}
}

// TestCLI_ExportShowSecret verifies export with --show-secret.
func TestCLI_ExportShowSecret(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")
	runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "exp")

	out, _, code := runCLI(t, pass, vf, "export", "exp", "--show-secret")
	if code != exitOK {
		t.Fatalf("export failed: %d", code)
	}
	if !strings.Contains(out, "secret=JBSWY3DPEHPK3PXP") {
		t.Errorf("expected raw secret in export, got: %q", out)
	}
}

// TestDecodeSecret_Sanitization verifies spaces, tabs, and hyphens are stripped.
func TestDecodeSecret_Sanitization(t *testing.T) {
	raw := "JBSW-Y3DP EHPK\t3PXP"
	dec, err := decodeSecret(raw)
	if err != nil {
		t.Fatalf("failed to decode formatted secret: %v", err)
	}
	cleanDec, _ := decodeSecret("JBSWY3DPEHPK3PXP")
	if string(dec) != string(cleanDec) {
		t.Errorf("sanitization mismatch: got %q, want %q", dec, cleanDec)
	}
}

// TestParseOTPAuthURI_CaseInsensitiveQuery verifies case-insensitive query parameter handling.
func TestParseOTPAuthURI_CaseInsensitiveQuery(t *testing.T) {
	uri := "otpauth://totp/Test:User?SECRET=JBSWY3DPEHPK3PXP&DIGITS=8&PERIOD=60&ALGORITHM=SHA256&ISSUER=Test"
	acc, err := parseOTPAuthURI(uri)
	if err != nil {
		t.Fatalf("failed to parse uppercase query URI: %v", err)
	}
	if acc.Digits != 8 || acc.Period != 60 || acc.Algorithm != "SHA256" || acc.Issuer != "Test" {
		t.Errorf("unexpected parsed fields: %+v", acc)
	}
}

// TestCLI_HOTPCounterProgression verifies that generating HOTP codes increments the stored counter.
func TestCLI_HOTPCounterProgression(t *testing.T) {
	vf := "--vault=" + filepath.Join(t.TempDir(), "vault.json")
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init")
	// Add HOTP account at counter 0 (RFC 4226 Appendix D: counter 0 -> 755224, counter 1 -> 287082)
	runCLI(t, pass, vf, "add", "hotp_seq", "--uri=otpauth://hotp/hotp_seq?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0")

	// First code call: should generate 755224 and advance counter to 1
	out1, _, code1 := runCLI(t, pass, vf, "code", "hotp_seq")
	if code1 != exitOK || !strings.Contains(out1, "755224") {
		t.Fatalf("first HOTP code got code=%d out=%q, want 755224", code1, out1)
	}

	// Second code call: should generate 287082 and advance counter to 2
	out2, _, code2 := runCLI(t, pass, vf, "code", "hotp_seq")
	if code2 != exitOK || !strings.Contains(out2, "287082") {
		t.Fatalf("second HOTP code got code=%d out=%q, want 287082", code2, out2)
	}
}

// ============================================================
// Benchmarks (Performance & Allocation Metrics)
// ============================================================

func BenchmarkHOTP(b *testing.B) {
	secret := []byte("12345678901234567890")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = hotp(secret, uint64(i), 6, "SHA1")
	}
}

func BenchmarkTOTP(b *testing.B) {
	secret := []byte("12345678901234567890")
	t := time.Unix(1111111111, 0)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = totp(secret, t, 30, 6, "SHA1")
	}
}

func BenchmarkPBKDF2_100k(b *testing.B) {
	salt := []byte("1234567890123456")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = deriveKey("password", salt, 100_000)
	}
}

func BenchmarkVaultEncryptDecrypt(b *testing.B) {
	salt := []byte("1234567890123456")
	key := deriveKey("testpass", salt, 1000)
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	aad := vaultAAD(vaultFormatVersion, vaultKDF, 1000, saltB64)
	data := VaultData{
		Accounts: []Account{
			{Name: "github", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Period: 30, Type: "totp"},
			{Name: "aws", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA256", Digits: 8, Period: 30, Type: "totp"},
		},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		nonce, ct, err := encryptVault(data, key, aad)
		if err != nil {
			b.Fatal(err)
		}
		_, err = decryptVault(nonce, ct, key, aad)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestCLI_CustomIterationsPreservedAcrossMutations verifies that initializing a vault with
// custom iterations (e.g. 5,000) preserves that exact iteration count across add, rename,
// remove, and HOTP code generation operations.
func TestCLI_CustomIterationsPreservedAcrossMutations(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.json")
	vf := "--vault=" + vaultPath
	pass := "pass\n"

	// 1. Init with 5,000 iterations
	runCLI(t, pass+pass, vf, "init", "--iterations=5000")

	checkIters := func(stage string) {
		t.Helper()
		raw, err := os.ReadFile(vaultPath)
		if err != nil {
			t.Fatalf("[%s] read vault: %v", stage, err)
		}
		var f VaultFile
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("[%s] parse vault: %v", stage, err)
		}
		if f.KDFIterations != 5000 {
			t.Errorf("[%s] KDFIterations = %d, want 5000", stage, f.KDFIterations)
		}
	}

	checkIters("after init")

	// 2. Add account
	runCLI(t, pass+"JBSWY3DPEHPK3PXP\n", vf, "add", "acc1")
	checkIters("after add")

	// 3. Rename account
	runCLI(t, pass, vf, "rename", "acc1", "acc2")
	checkIters("after rename")

	// 4. Add HOTP account and generate code (mutates counter on disk)
	runCLI(t, pass, vf, "add", "hotp_acc", "--uri=otpauth://hotp/hotp_acc?secret=JBSWY3DPEHPK3PXP&counter=0")
	checkIters("after add HOTP")

	runCLI(t, pass, vf, "code", "hotp_acc")
	checkIters("after code HOTP")

	// 5. Remove account
	runCLI(t, pass, vf, "remove", "acc2")
	checkIters("after remove")
}

// TestCLI_VerifyHOTP_SaveFailure verifies that if saving the updated HOTP counter fails,
// verify returns exitError and does NOT claim the code was valid.
func TestCLI_VerifyHOTP_SaveFailure(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.json")
	vf := "--vault=" + vaultPath
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init", "--iterations=1000")
	runCLI(t, pass, vf, "add", "h1", "--uri=otpauth://hotp/h1?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0")

	// Make the vault file read-only so saving fails
	if err := os.Chmod(vaultPath, 0400); err != nil {
		t.Skip("skipping read-only file test on unsupported platform")
	}
	defer os.Chmod(vaultPath, 0600) // cleanup

	// Counter 0 generates 755224. Verify should try to save counter 1 and fail.
	out, errOut, code := runCLI(t, pass, vf, "verify", "h1", "755224")
	if code == exitOK {
		t.Errorf("expected error when saving counter fails, got code=0 (stdout: %q, stderr: %q)", out, errOut)
	}
}

// TestVault_MalformedHeaders tests validation of corrupted or illegal header fields.
func TestVault_MalformedHeaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")

	validSalt := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	validNonce := base64.StdEncoding.EncodeToString(make([]byte, 12))
	validCT := base64.StdEncoding.EncodeToString(make([]byte, 32))

	tests := []struct {
		name string
		vf   VaultFile
	}{
		{
			name: "bad format version",
			vf: VaultFile{
				FormatVersion: 99,
				KDF:           vaultKDF,
				KDFIterations: 1000,
				KDFSalt:       validSalt,
				Nonce:         validNonce,
				Ciphertext:    validCT,
			},
		},
		{
			name: "unsupported KDF",
			vf: VaultFile{
				FormatVersion: 1,
				KDF:           "MD5-CRYPT",
				KDFIterations: 1000,
				KDFSalt:       validSalt,
				Nonce:         validNonce,
				Ciphertext:    validCT,
			},
		},
		{
			name: "iterations too low",
			vf: VaultFile{
				FormatVersion: 1,
				KDF:           vaultKDF,
				KDFIterations: 50,
				KDFSalt:       validSalt,
				Nonce:         validNonce,
				Ciphertext:    validCT,
			},
		},
		{
			name: "iterations too high",
			vf: VaultFile{
				FormatVersion: 1,
				KDF:           vaultKDF,
				KDFIterations: 99_000_000,
				KDFSalt:       validSalt,
				Nonce:         validNonce,
				Ciphertext:    validCT,
			},
		},
		{
			name: "salt too short",
			vf: VaultFile{
				FormatVersion: 1,
				KDF:           vaultKDF,
				KDFIterations: 1000,
				KDFSalt:       base64.StdEncoding.EncodeToString([]byte("short")),
				Nonce:         validNonce,
				Ciphertext:    validCT,
			},
		},
		{
			name: "nonce wrong size",
			vf: VaultFile{
				FormatVersion: 1,
				KDF:           vaultKDF,
				KDFIterations: 1000,
				KDFSalt:       validSalt,
				Nonce:         base64.StdEncoding.EncodeToString([]byte("1234")),
				Ciphertext:    validCT,
			},
		},
		{
			name: "ciphertext too short",
			vf: VaultFile{
				FormatVersion: 1,
				KDF:           vaultKDF,
				KDFIterations: 1000,
				KDFSalt:       validSalt,
				Nonce:         validNonce,
				Ciphertext:    base64.StdEncoding.EncodeToString([]byte("123")),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.vf)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, _, _, _, err = loadVault(path, "testpass")
			if err == nil {
				t.Fatalf("[%s] expected loadVault error for malformed header, got nil", tc.name)
			}
		})
	}
}

// TestVault_AADHeaderTampering verifies that AES-GCM Additional Authenticated Data (AAD)
// cryptographically detects and rejects tampering of the JSON envelope headers via the
// full loadVault path. Note: changing kdf_iterations also changes the derived key, so
// this test proves the AAD + key combination fails. For an isolated AAD-only proof,
// see TestVault_AADDirectProof.
func TestVault_AADHeaderTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	const iters = 1000
	salt := []byte("1234567890123456")
	key := deriveKey("testpass", salt, iters)
	data := VaultData{Accounts: []Account{{Name: "acc1", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Period: 30, Type: "totp"}}}

	if err := saveVault(path, data, key, salt, iters); err != nil {
		t.Fatalf("saveVault: %v", err)
	}

	// Read valid vault file
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	var vf VaultFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Tamper with kdf_iterations in JSON header (e.g. change 1000 to 2000)
	vf.KDFIterations = 2000
	tamperedJSON, _ := json.Marshal(vf)
	if err := os.WriteFile(path, tamperedJSON, 0600); err != nil {
		t.Fatalf("writeFile: %v", err)
	}

	// Attempting to load must fail GCM authentication (errWrongPassword)
	_, _, _, _, err = loadVault(path, "testpass")
	if !errors.Is(err, errWrongPassword) {
		t.Errorf("expected errWrongPassword when header AAD is tampered, got: %v", err)
	}
}

// TestVault_AADDirectProof directly proves that AES-GCM AAD is enforced
// independently of the encryption key. It uses the IDENTICAL key and ciphertext
// but passes different AAD to decryptVault(). This specifically isolates the
// AAD binding from key-derivation effects — the proof the reviewer requested.
func TestVault_AADDirectProof(t *testing.T) {
	salt := []byte("testsalt12345678") // exactly 16 bytes
	key := pbkdf2([]byte("password"), salt, 1000, 32)
	saltB64 := base64.StdEncoding.EncodeToString(salt)

	// Encrypt with the legitimate AAD.
	realAAD := vaultAAD(vaultFormatVersion, vaultKDF, 1000, saltB64)
	data := VaultData{Accounts: []Account{
		{Name: "proof-acct", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Period: 30, Type: "totp"},
	}}
	nonce, ciphertext, err := encryptVault(data, key, realAAD)
	if err != nil {
		t.Fatalf("encryptVault: %v", err)
	}

	// Attempt decryption with the SAME key and ciphertext but ALTERED AAD.
	// This simulates an attacker modifying the JSON header without re-encrypting.
	// Only the AAD differs; the key is identical.
	tamperedAAD := vaultAAD(vaultFormatVersion, vaultKDF, 1001, saltB64) // iterations changed: 1000→1001
	_, err = decryptVault(nonce, ciphertext, key, tamperedAAD)
	if err == nil {
		t.Fatal("SECURITY: decryptVault succeeded with tampered AAD and same key — AAD binding is broken!")
	}

	// Sanity check: the real AAD must still work.
	dec, err := decryptVault(nonce, ciphertext, key, realAAD)
	if err != nil {
		t.Fatalf("decryptVault with correct AAD failed unexpectedly: %v", err)
	}
	if len(dec.Accounts) != 1 || dec.Accounts[0].Name != "proof-acct" {
		t.Errorf("decrypted data mismatch: %+v", dec.Accounts)
	}
}

// TestVault_ConcurrentHOTPAccess verifies that multiple concurrent processes/goroutines
// generating HOTP codes acquire the lock cleanly and never produce duplicate codes.
func TestVault_ConcurrentHOTPAccess(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.json")
	vf := "--vault=" + vaultPath
	pass := "pass\n"

	runCLI(t, pass+pass, vf, "init", "--iterations=1000")
	runCLI(t, pass, vf, "add", "hotp_conc", "--uri=otpauth://hotp/hotp_conc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0")

	const n = 5
	results := make(chan string, n)
	errorsChan := make(chan error, n)

	for i := 0; i < n; i++ {
		go func() {
			out, _, code := runCLI(t, pass, vf, "code", "hotp_conc")
			if code != exitOK {
				errorsChan <- fmt.Errorf("exit code %d: %s", code, out)
				return
			}
			results <- strings.TrimSpace(out)
		}()
	}

	seen := make(map[string]bool)
	for i := 0; i < n; i++ {
		select {
		case err := <-errorsChan:
			t.Fatalf("concurrent HOTP code generation failed: %v", err)
		case token := <-results:
			if seen[token] {
				t.Fatalf("duplicate HOTP token generated under concurrency: %s", token)
			}
			seen[token] = true
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for concurrent HOTP execution")
		}
	}
}
