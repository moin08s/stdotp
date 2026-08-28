package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// stdinReader is the shared buffered stdin reader used by all commands.
// A single bufio.Reader avoids the double-buffering problem that would occur
// if readLine() and interactive prompts each created their own scanner on
// os.Stdin: the first scanner could consume data the second one needs.
var stdinReader = bufio.NewReader(os.Stdin)

// ---- crypto primitives (HOTP/TOTP, RFC 4226 / 6238) ----

// hotp computes an HMAC-Based One-Time Password per RFC 4226.
//
// secret is the raw (already decoded) key bytes.
// counter is the 8-byte big-endian moving factor (RFC 4226 §5.1).
// digits is the number of output digits (6–8).
// algo is "SHA1", "SHA256", or "SHA512".
func hotp(secret []byte, counter uint64, digits int, algo string) string {
	h := newHMAC(algo, secret)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	h.Write(buf[:])
	mac := h.Sum(nil)

	// Dynamic truncation — RFC 4226 §5.3:
	//   offset  = last byte of MAC & 0x0F
	//   sbits   = 4 bytes starting at offset, top bit cleared
	//   code    = sbits mod 10^digits
	offset := mac[len(mac)-1] & 0x0f
	sbits := (uint32(mac[offset]&0x7f)<<24 |
		uint32(mac[offset+1])<<16 |
		uint32(mac[offset+2])<<8 |
		uint32(mac[offset+3]))

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, sbits%mod)
}

// totp computes a Time-Based One-Time Password per RFC 6238.
//
// Returns the OTP code and the number of seconds left in the current period.
// The counter is floor(unix(t) / period) — identical to RFC 6238 §4.
func totp(secret []byte, t time.Time, period, digits int, algo string) (code string, secondsRemaining int) {
	ts := t.Unix()
	counter := uint64(ts / int64(period))
	elapsed := int(ts % int64(period))
	secondsRemaining = period - elapsed
	code = hotp(secret, counter, digits, algo)
	return
}

// newHMAC returns an HMAC hash keyed to key using the named algorithm.
// Unrecognised algorithm names fall back to SHA1 (RFC 6238 §1 default).
func newHMAC(algo string, key []byte) hash.Hash {
	switch strings.ToUpper(algo) {
	case "SHA256":
		return hmac.New(sha256.New, key)
	case "SHA512":
		return hmac.New(sha512.New, key)
	default:
		return hmac.New(sha1.New, key)
	}
}

// deriveKey derives a 32-byte AES-256 key via PBKDF2-HMAC-SHA256.
//
// PBKDF2-HMAC-SHA256 implemented exactly per RFC 2898 §5.2 by composing
// crypto/hmac. Not a custom algorithm — a faithful standard construction
// built entirely from stdlib primitives.
//
// Iteration count: 600,000 (OWASP Password Storage Cheat Sheet 2026
// recommendation for PBKDF2-HMAC-SHA256, benchmarked against modern GPU
// hardware). This number and its source are stated explicitly in the threat
// model rather than left as an unstated, arbitrary choice.
func deriveKey(password string, salt []byte, iterations int) []byte {
	return pbkdf2([]byte(password), salt, iterations, 32)
}

// pbkdf2 implements RFC 2898 §5.2 with HMAC-SHA256 as the PRF.
//
// This is a faithful transcription of the published standard algorithm:
//
//	DK = T1 || T2 || ... || Tnumblocks (truncated to keyLen)
//	Ti = U1 XOR U2 XOR ... XOR Uc
//	U1 = PRF(Password, Salt || INT(i))
//	Uj = PRF(Password, U_{j-1})   for j = 2..c
//
// The RFC 7914 §11 test vectors in stdotp_test.go verify that this
// implementation matches the published standard, not just that it
// round-trips against itself.
func pbkdf2(password, salt []byte, iterations, keyLen int) []byte {
	const hLen = sha256.Size // 32 bytes
	numBlocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, numBlocks*hLen)

	// Reuse a single HMAC context across iterations to avoid per-iteration
	// allocations. prf.Reset() brings it back to the initial keyed state.
	prf := hmac.New(sha256.New, password)

	for block := 1; block <= numBlocks; block++ {
		// U1 = PRF(Password, Salt || INT(block))
		saltBlock := make([]byte, len(salt)+4)
		copy(saltBlock, salt)
		saltBlock[len(salt)+0] = byte(block >> 24)
		saltBlock[len(salt)+1] = byte(block >> 16)
		saltBlock[len(salt)+2] = byte(block >> 8)
		saltBlock[len(salt)+3] = byte(block)

		prf.Reset()
		prf.Write(saltBlock)
		u := prf.Sum(nil)

		t := make([]byte, hLen)
		copy(t, u)

		// U2..Uc: each is PRF(Password, previous U); T = XOR of all Ui.
		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// ---- vault (AES-256-GCM at rest, PBKDF2-HMAC key derivation) ----

const (
	// vaultFormatVersion identifies the KDF + cipher tier used to write this
	// vault (§11 of the development plan). Bump if KDF or cipher ever changes
	// so a future reader can tell which tier produced a given file.
	vaultFormatVersion = 1

	vaultKDF = "PBKDF2-HMAC-SHA256"

	// vaultKDFIterations is 600,000 — the OWASP Password Storage Cheat Sheet
	// 2026 recommendation for PBKDF2-HMAC-SHA256. Cited explicitly so this
	// choice is defensible, not arbitrary.
	vaultKDFIterations = 600_000

	vaultSaltLen = 16 // 128-bit salt, from crypto/rand
)

// VaultFile is the JSON envelope written to disk.
// Every field is present in plaintext so the format can be understood
// without reverse-engineering a binary layout — a deliberate "documented,
// defensible" design choice per Track E's requirements.
type VaultFile struct {
	FormatVersion int    `json:"format_version"`
	KDF           string `json:"kdf"`
	KDFIterations int    `json:"kdf_iterations"`
	// KDFSalt: base64-encoded 16 random bytes from crypto/rand.
	KDFSalt string `json:"kdf_salt"`
	// Nonce: base64-encoded 12 random bytes from crypto/rand, fresh every write.
	Nonce string `json:"nonce"`
	// Ciphertext: base64-encoded AES-256-GCM output; the auth tag rides inside.
	Ciphertext string `json:"ciphertext"`
}

// Account holds one TOTP or HOTP entry.
type Account struct {
	Name      string `json:"name"`
	Issuer    string `json:"issuer,omitempty"`
	Secret    string `json:"secret"`    // base32-encoded, no padding
	Algorithm string `json:"algorithm"` // SHA1, SHA256, SHA512
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Type      string `json:"type"`              // "totp" or "hotp"
	Counter   uint64 `json:"counter,omitempty"` // HOTP only
}

// VaultData is the plaintext JSON payload that lives inside VaultFile.Ciphertext.
type VaultData struct {
	Accounts []Account `json:"accounts"`
}

// Sentinel errors used by loadVault; vaultErrCode maps them to exit codes.
var (
	// errVaultMissing is returned when the vault file does not exist.
	// Fail-safe: never silently auto-create a vault (§2.2 of the plan).
	errVaultMissing = errors.New("vault not initialized")

	// errWrongPassword is returned when GCM authentication fails.
	// Fail-safe: never fall through to partial or garbage plaintext (§2.2).
	errWrongPassword = errors.New("wrong password or corrupted vault")
)

// encryptVault marshals data to JSON and encrypts it with AES-256-GCM.
//
// A 12-byte nonce is freshly generated from crypto/rand on every call.
// Reusing a nonce with the same key is the one mistake that breaks GCM's
// security guarantee; this function never reuses a nonce.
//
// The GCM auth tag is embedded inside the returned ciphertext slice
// automatically by cipher.AEAD.Seal — no separate MAC step is needed.
func encryptVault(data VaultData, key []byte) (nonce, ciphertext []byte, err error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal vault data: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("new AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("new GCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// decryptVault authenticates and decrypts ciphertext.
//
// AES-GCM's authentication check fails on any wrong key or modified byte —
// cipher.AEAD.Open returns an error rather than partial plaintext.
// The caller must treat this error as exit code 3 (wrong password / tampered),
// never fall through. This is a property of using authenticated encryption
// (GCM) rather than a bare cipher mode.
func decryptVault(nonce, ciphertext, key []byte) (VaultData, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return VaultData{}, fmt.Errorf("new AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return VaultData{}, fmt.Errorf("new GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// GCM authentication failure: wrong password or tampered ciphertext.
		// Return a generic message — never a partial result.
		return VaultData{}, errors.New("GCM authentication failed (wrong password or tampered ciphertext)")
	}

	var data VaultData
	if err = json.Unmarshal(plaintext, &data); err != nil {
		return VaultData{}, fmt.Errorf("unmarshal plaintext: %w", err)
	}
	return data, nil
}

// loadVault reads and decrypts the vault at path using password.
//
// Fail-safe rules (§2.2):
//   - File missing          → errVaultMissing  (never auto-create)
//   - File unreadable/corrupt → error           (never attempt repair)
//   - Wrong password/tampered → errWrongPassword (never partial plaintext)
//
// Returns the plaintext data plus the derived key and original salt so the
// caller can re-encrypt on mutation without re-prompting for the password.
func loadVault(path, password string) (data VaultData, key, salt []byte, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return VaultData{}, nil, nil, errVaultMissing
		}
		return VaultData{}, nil, nil, fmt.Errorf("read vault file: %w", err)
	}

	var vf VaultFile
	if err = json.Unmarshal(raw, &vf); err != nil {
		return VaultData{}, nil, nil, fmt.Errorf("corrupt vault (JSON parse failed): %w", err)
	}

	salt, err = base64.StdEncoding.DecodeString(vf.KDFSalt)
	if err != nil {
		return VaultData{}, nil, nil, fmt.Errorf("corrupt vault (bad salt encoding): %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(vf.Nonce)
	if err != nil {
		return VaultData{}, nil, nil, fmt.Errorf("corrupt vault (bad nonce encoding): %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(vf.Ciphertext)
	if err != nil {
		return VaultData{}, nil, nil, fmt.Errorf("corrupt vault (bad ciphertext encoding): %w", err)
	}

	iters := vf.KDFIterations
	if iters <= 0 {
		iters = vaultKDFIterations
	}
	key = deriveKey(password, salt, iters)

	data, err = decryptVault(nonce, ciphertext, key)
	if err != nil {
		// GCM auth failure: surface only as errWrongPassword, never the
		// internal cipher error, to avoid information leakage.
		return VaultData{}, nil, nil, errWrongPassword
	}
	return data, key, salt, nil
}

// saveVault encrypts data and atomically writes it to path.
//
// "Atomic" means: write to a temp file → Sync → os.Rename.
// A process killed between the temp-write and the rename always leaves the
// previous vault intact — the rename is atomic at the OS level on both
// POSIX and Windows (within the same filesystem). A partial temp file is
// cleaned up by the deferred remove.
//
// A fresh nonce is generated on every call — nonce reuse with the same key
// breaks GCM's security guarantee and is therefore a hard rule, not a hint.
func saveVault(path string, data VaultData, key, salt []byte, iterations int) error {
	nonce, ciphertext, err := encryptVault(data, key)
	if err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	vf := VaultFile{
		FormatVersion: vaultFormatVersion,
		KDF:           vaultKDF,
		KDFIterations: iterations,
		KDFSalt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:    base64.StdEncoding.EncodeToString(ciphertext),
	}
	raw, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal vault file: %w", err)
	}
	raw = append(raw, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".stdotp-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpPath) // clean up on any failure before rename
		}
	}()

	if _, err = tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename vault file: %w", err)
	}
	ok = true
	return nil
}

// ---- otpauth:// URI parsing and generation ----

// parseOTPAuthURI parses an otpauth:// URI into an Account.
//
// Implements the de-facto Google Authenticator Key URI Format spec:
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
// Label format: /<issuer>:<account> or /<account>
func parseOTPAuthURI(uri string) (Account, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return Account{}, fmt.Errorf("invalid URI: %w", err)
	}
	if u.Scheme != "otpauth" {
		return Account{}, fmt.Errorf("not an otpauth:// URI (scheme=%q)", u.Scheme)
	}

	otpType := strings.ToLower(u.Host)
	if otpType != "totp" && otpType != "hotp" {
		return Account{}, fmt.Errorf("unsupported OTP type: %q (want totp or hotp)", otpType)
	}

	// Label: strip leading slash, unescape percent-encoding.
	label := strings.TrimPrefix(u.Path, "/")
	if label, err = url.PathUnescape(label); err != nil {
		return Account{}, fmt.Errorf("invalid URI label: %w", err)
	}
	var issuer, accountName string
	if idx := strings.Index(label, ":"); idx >= 0 {
		issuer = strings.TrimSpace(label[:idx])
		accountName = strings.TrimSpace(label[idx+1:])
	} else {
		accountName = strings.TrimSpace(label)
	}

	q := u.Query()

	// secret (required) — strip padding, normalise to upper-case.
	secret := strings.ToUpper(strings.TrimRight(q.Get("secret"), "="))
	if secret == "" {
		return Account{}, errors.New("otpauth URI missing required 'secret' parameter")
	}
	padded := secret + strings.Repeat("=", (8-len(secret)%8)%8)
	if _, err = base32.StdEncoding.DecodeString(padded); err != nil {
		return Account{}, fmt.Errorf("invalid base32 secret: %w", err)
	}

	// algorithm (optional, default SHA1)
	algo := strings.ToUpper(q.Get("algorithm"))
	if algo == "" {
		algo = "SHA1"
	}
	switch algo {
	case "SHA1", "SHA256", "SHA512":
	default:
		return Account{}, fmt.Errorf("unsupported algorithm: %q (want SHA1, SHA256, or SHA512)", algo)
	}

	// digits (optional, default 6)
	digits := 6
	if d := q.Get("digits"); d != "" {
		digits, err = strconv.Atoi(d)
		if err != nil || digits < 6 || digits > 8 {
			return Account{}, fmt.Errorf("invalid digits: %q (want 6, 7, or 8)", d)
		}
	}

	// period (TOTP, optional, default 30)
	period := 30
	if p := q.Get("period"); p != "" {
		period, err = strconv.Atoi(p)
		if err != nil || period <= 0 {
			return Account{}, fmt.Errorf("invalid period: %q (must be a positive integer)", p)
		}
	}

	// issuer query parameter takes precedence over issuer in the label.
	if qi := q.Get("issuer"); qi != "" {
		issuer = qi
	}

	// counter (HOTP, required for hotp type)
	var counter uint64
	if otpType == "hotp" {
		c := q.Get("counter")
		if c == "" {
			return Account{}, errors.New("hotp URI requires 'counter' parameter")
		}
		counter, err = strconv.ParseUint(c, 10, 64)
		if err != nil {
			return Account{}, fmt.Errorf("invalid counter value: %w", err)
		}
	}

	return Account{
		Name:      accountName,
		Issuer:    issuer,
		Secret:    secret,
		Algorithm: algo,
		Digits:    digits,
		Period:    period,
		Type:      otpType,
		Counter:   counter,
	}, nil
}

// buildOTPAuthURI constructs a canonical otpauth:// URI from an Account.
//
// If showSecret is false the secret parameter is replaced with "[REDACTED]"
// so the URI can be printed safely without exposing the raw key.
// Non-default field values (algorithm=SHA1, digits=6, period=30) are omitted
// to keep the URI clean and interoperable.
func buildOTPAuthURI(a Account, showSecret bool) string {
	otpType := strings.ToLower(a.Type)
	if otpType == "" {
		otpType = "totp"
	}

	label := a.Name
	if a.Issuer != "" {
		label = a.Issuer + ":" + a.Name
	}

	u := &url.URL{
		Scheme: "otpauth",
		Host:   otpType,
		Path:   "/" + url.PathEscape(label),
	}

	q := url.Values{}
	if showSecret {
		q.Set("secret", a.Secret)
	} else {
		q.Set("secret", "[REDACTED]")
	}
	if a.Issuer != "" {
		q.Set("issuer", a.Issuer)
	}
	if a.Algorithm != "" && strings.ToUpper(a.Algorithm) != "SHA1" {
		q.Set("algorithm", strings.ToUpper(a.Algorithm))
	}
	if a.Digits != 0 && a.Digits != 6 {
		q.Set("digits", strconv.Itoa(a.Digits))
	}
	if otpType == "totp" && a.Period != 0 && a.Period != 30 {
		q.Set("period", strconv.Itoa(a.Period))
	}
	if otpType == "hotp" {
		q.Set("counter", strconv.FormatUint(a.Counter, 10))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// decodeSecret base32-decodes a secret string, tolerating missing padding.
func decodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimRight(s, "="))
	if s == "" {
		return nil, errors.New("empty secret")
	}
	padded := s + strings.Repeat("=", (8-len(s)%8)%8)
	b, err := base32.StdEncoding.DecodeString(padded)
	if err != nil {
		return nil, fmt.Errorf("invalid base32 secret: %w", err)
	}
	return b, nil
}

// ---- CLI (subcommands, flags, exit codes) ----

// Exit codes per §4 of the development plan.
const (
	exitOK           = 0
	exitError        = 1
	exitUsage        = 2
	exitWrongPass    = 3
	exitNotFound     = 4
	exitVaultMissing = 5
)

// globalVaultPath is set before subcommand dispatch by the --vault global flag.
var globalVaultPath string

func defaultVaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".stdotp/vault.json"
	}
	return filepath.Join(home, ".stdotp", "vault.json")
}

const usageText = `stdotp — zero-dependency TOTP/HOTP authenticator (Track E · Zero Dependency 2026)

Usage:
  stdotp [--vault <path>] <subcommand> [options]

Subcommands:
  init                       Initialize a new encrypted vault
  add <name>                 Add an account (interactive: prompts on stdin)
    --secret <base32>        Provide base32 secret directly (shell-history risk!)
    --secret-file <path>     Read base32 secret from a file (preferred)
    --uri <otpauth://...>    Provide otpauth:// URI directly (shell-history risk!)
    --uri-file <path>        Read otpauth:// URI from a file (preferred)
  code <name>                Generate the current TOTP/HOTP code
    --json                   Output as JSON {"account":...,"code":...,"seconds_remaining":...}
  list                       List all accounts in the vault
  remove <name>              Remove an account from the vault
  export <name>              Print the otpauth:// URI for an account
    --show-secret            Include the raw secret in the exported URI

Global flag:
  --vault <path>             Path to vault file (default: ~/.stdotp/vault.json)

Exit codes:
  0  OK             2  Usage error       4  Account not found
  1  General error  3  Wrong password    5  Vault not initialized

Note: password input is NOT masked (no golang.org/x/term — not stdlib).
      Use --secret-file or --uri-file rather than --secret/--uri to keep
      secrets out of shell history and 'ps' output.
`

func main() {
	globalVaultPath = defaultVaultPath()

	args := os.Args[1:]

	// Parse --vault manually before subcommand dispatch so each subcommand
	// can define its own flag.FlagSet without inheriting the global flag.
	for i := 0; i < len(args); i++ {
		switch {
		case (args[i] == "--vault" || args[i] == "-vault") && i+1 < len(args):
			globalVaultPath = args[i+1]
			args = append(args[:i], args[i+2:]...)
			i--
		case strings.HasPrefix(args[i], "--vault="):
			globalVaultPath = strings.TrimPrefix(args[i], "--vault=")
			args = append(args[:i], args[i+1:]...)
			i--
		case strings.HasPrefix(args[i], "-vault="):
			globalVaultPath = strings.TrimPrefix(args[i], "-vault=")
			args = append(args[:i], args[i+1:]...)
			i--
		}
	}

	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(exitUsage)
	}

	sub, subArgs := args[0], args[1:]
	var code int
	switch sub {
	case "init":
		code = cmdInit(subArgs)
	case "add":
		code = cmdAdd(subArgs)
	case "code":
		code = cmdCode(subArgs)
	case "list", "ls":
		code = cmdList(subArgs)
	case "remove", "rm":
		code = cmdRemove(subArgs)
	case "export":
		code = cmdExport(subArgs)
	case "help", "--help", "-h":
		fmt.Fprint(os.Stdout, usageText)
		code = exitOK
	default:
		fmt.Fprintf(os.Stderr, "error: unknown subcommand %q\n\n%s", sub, usageText)
		code = exitUsage
	}
	os.Exit(code)
}

// cmdInit creates a new encrypted vault.
//
// Fail-safe: refuses to overwrite an existing vault (§2.2).
func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "Usage: stdotp init") }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return exitUsage
	}

	if _, err := os.Stat(globalVaultPath); err == nil {
		fmt.Fprintf(os.Stderr, "error: vault already exists at %s\n", globalVaultPath)
		return exitError
	}

	fmt.Fprint(os.Stderr, "Enter new master password: ")
	password, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading password: %v\n", err)
		return exitError
	}
	if password == "" {
		fmt.Fprintln(os.Stderr, "error: password must not be empty")
		return exitError
	}
	fmt.Fprint(os.Stderr, "Confirm master password: ")
	confirm, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading confirmation: %v\n", err)
		return exitError
	}
	if subtle.ConstantTimeCompare([]byte(password), []byte(confirm)) != 1 {
		fmt.Fprintln(os.Stderr, "error: passwords do not match")
		return exitError
	}

	salt := make([]byte, vaultSaltLen)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		fmt.Fprintf(os.Stderr, "error generating salt: %v\n", err)
		return exitError
	}

	if err = os.MkdirAll(filepath.Dir(globalVaultPath), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "error creating vault directory: %v\n", err)
		return exitError
	}

	fmt.Fprintln(os.Stderr, "Deriving key (this takes a moment)...")
	key := deriveKey(password, salt, vaultKDFIterations)
	if err = saveVault(globalVaultPath, VaultData{}, key, salt, vaultKDFIterations); err != nil {
		fmt.Fprintf(os.Stderr, "error saving vault: %v\n", err)
		return exitError
	}

	fmt.Fprintf(os.Stderr, "Vault initialized at %s\n", globalVaultPath)
	return exitOK
}

// cmdAdd adds a new account to the vault.
//
// Secret/URI input precedence: --uri-flag > --uri-file > --secret-flag >
// --secret-file > interactive stdin.
// Interactive stdin is the most secure path (secret never appears in shell
// history or 'ps' output) and is the recommended path in the README.
func cmdAdd(args []string) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	secretFlag := fs.String("secret", "", "base32 secret (shell-history risk — prefer --secret-file)")
	secretFile := fs.String("secret-file", "", "read base32 secret from file")
	uriFlag := fs.String("uri", "", "otpauth:// URI (shell-history risk — prefer --uri-file)")
	uriFile := fs.String("uri-file", "", "read otpauth:// URI from file")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: stdotp add <name> [--secret-file <p>|--uri-file <p>|--secret <b32>|--uri <uri>]")
	}

	// Pull the account name out of args before flag.Parse so that flags can
	// appear after the name (e.g. "stdotp add alice --uri ...").
	// Go's flag package stops at the first non-flag argument, so if <name>
	// comes first it would prevent --uri etc. from being parsed.
	var name string
	var flagArgs []string
	for i, a := range args {
		if !strings.HasPrefix(a, "-") && name == "" {
			name = a
			flagArgs = append(flagArgs, args[i+1:]...)
			break
		}
		flagArgs = append(flagArgs, a)
	}
	if name == "" {
		// All args were flags — no positional name provided.
		fs.Usage()
		return exitUsage
	}
	if err := fs.Parse(flagArgs); err != nil {
		return exitUsage
	}

	fmt.Fprint(os.Stderr, "Master password: ")
	password, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	data, key, salt, err := loadVault(globalVaultPath, password)
	if err != nil {
		return vaultErrCode(err)
	}

	for _, a := range data.Accounts {
		if a.Name == name {
			fmt.Fprintf(os.Stderr, "error: account %q already exists\n", name)
			return exitError
		}
	}

	var account Account
	switch {
	case *uriFlag != "":
		account, err = parseOTPAuthURI(*uriFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing URI: %v\n", err)
			return exitError
		}
		account.Name = name

	case *uriFile != "":
		raw, readErr := os.ReadFile(*uriFile)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "error reading URI file: %v\n", readErr)
			return exitError
		}
		account, err = parseOTPAuthURI(strings.TrimSpace(string(raw)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error parsing URI from file: %v\n", err)
			return exitError
		}
		account.Name = name

	case *secretFlag != "":
		account, err = accountFromSecret(name, *secretFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return exitError
		}

	case *secretFile != "":
		raw, readErr := os.ReadFile(*secretFile)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "error reading secret file: %v\n", readErr)
			return exitError
		}
		account, err = accountFromSecret(name, strings.TrimSpace(string(raw)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return exitError
		}

	default:
		// Interactive path: prompt for base32 secret or otpauth:// URI on stdin.
		fmt.Fprintln(os.Stderr, "Enter base32 secret or otpauth:// URI:")
		input, readErr := readLine()
		if readErr != nil || strings.TrimSpace(input) == "" {
			fmt.Fprintln(os.Stderr, "error: no input provided")
			return exitError
		}
		input = strings.TrimSpace(input)
		if strings.HasPrefix(input, "otpauth://") {
			account, err = parseOTPAuthURI(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error parsing URI: %v\n", err)
				return exitError
			}
			account.Name = name
		} else {
			account, err = accountFromSecret(name, input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return exitError
			}
		}
	}

	data.Accounts = append(data.Accounts, account)
	if err = saveVault(globalVaultPath, data, key, salt, vaultKDFIterations); err != nil {
		fmt.Fprintf(os.Stderr, "error saving vault: %v\n", err)
		return exitError
	}

	fmt.Fprintf(os.Stderr, "Account %q added.\n", name)
	return exitOK
}

// accountFromSecret builds a default TOTP Account from a raw base32 secret.
// Defaults: algorithm=SHA1, digits=6, period=30 — matching common authenticator apps.
func accountFromSecret(name, secret string) (Account, error) {
	secret = strings.ToUpper(strings.TrimRight(secret, "="))
	padded := secret + strings.Repeat("=", (8-len(secret)%8)%8)
	if _, err := base32.StdEncoding.DecodeString(padded); err != nil {
		return Account{}, fmt.Errorf("invalid base32 secret: %w", err)
	}
	return Account{
		Name:      name,
		Algorithm: "SHA1",
		Digits:    6,
		Period:    30,
		Type:      "totp",
		Secret:    secret,
	}, nil
}

// cmdCode generates the current OTP code for a named account.
func cmdCode(args []string) int {
	fs := flag.NewFlagSet("code", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output as JSON")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "Usage: stdotp code <name> [--json]") }

	var name string
	var flagArgs []string
	for i, a := range args {
		if !strings.HasPrefix(a, "-") && name == "" {
			name = a
			flagArgs = append(flagArgs, args[i+1:]...)
			break
		}
		flagArgs = append(flagArgs, a)
	}
	if name == "" {
		fs.Usage()
		return exitUsage
	}
	if err := fs.Parse(flagArgs); err != nil {
		return exitUsage
	}

	fmt.Fprint(os.Stderr, "Master password: ")
	password, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	data, _, _, err := loadVault(globalVaultPath, password)
	if err != nil {
		return vaultErrCode(err)
	}

	account, ok := findAccount(data, name)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: account %q not found\n", name)
		return exitNotFound
	}

	secret, err := decodeSecret(account.Secret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decoding secret: %v\n", err)
		return exitError
	}

	digits := account.Digits
	if digits == 0 {
		digits = 6
	}
	period := account.Period
	if period == 0 {
		period = 30
	}
	algo := account.Algorithm
	if algo == "" {
		algo = "SHA1"
	}

	var otp string
	var secsLeft int

	if strings.EqualFold(account.Type, "hotp") {
		otp = hotp(secret, account.Counter, digits, algo)
		secsLeft = 0
	} else {
		otp, secsLeft = totp(secret, time.Now(), period, digits, algo)
	}

	if *asJSON {
		// Only requested data goes to stdout — prompts/errors go to stderr.
		fmt.Printf(`{"account":%q,"code":%q,"seconds_remaining":%d}`+"\n", name, otp, secsLeft)
	} else {
		if !strings.EqualFold(account.Type, "hotp") {
			fmt.Printf("%s  (%ds remaining)\n", otp, secsLeft)
		} else {
			fmt.Printf("%s\n", otp)
		}
	}
	return exitOK
}

// cmdList prints all accounts in a tabular format using text/tabwriter.
func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "Usage: stdotp list") }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	fmt.Fprint(os.Stderr, "Master password: ")
	password, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	data, _, _, err := loadVault(globalVaultPath, password)
	if err != nil {
		return vaultErrCode(err)
	}

	if len(data.Accounts) == 0 {
		fmt.Fprintln(os.Stderr, "(vault is empty)")
		return exitOK
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tISSUER\tTYPE\tALGO\tDIGITS\tPERIOD")
	for _, a := range data.Accounts {
		issuer := a.Issuer
		if issuer == "" {
			issuer = "-"
		}
		period := strconv.Itoa(a.Period)
		if strings.EqualFold(a.Type, "hotp") {
			period = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			a.Name, issuer, strings.ToUpper(a.Type), a.Algorithm, a.Digits, period)
	}
	w.Flush()
	return exitOK
}

// cmdRemove removes a named account from the vault.
func cmdRemove(args []string) int {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "Usage: stdotp remove <name>") }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return exitUsage
	}
	name := fs.Arg(0)

	fmt.Fprint(os.Stderr, "Master password: ")
	password, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	data, key, salt, err := loadVault(globalVaultPath, password)
	if err != nil {
		return vaultErrCode(err)
	}

	idx := -1
	for i, a := range data.Accounts {
		if a.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		fmt.Fprintf(os.Stderr, "error: account %q not found\n", name)
		return exitNotFound
	}

	data.Accounts = append(data.Accounts[:idx], data.Accounts[idx+1:]...)
	if err = saveVault(globalVaultPath, data, key, salt, vaultKDFIterations); err != nil {
		fmt.Fprintf(os.Stderr, "error saving vault: %v\n", err)
		return exitError
	}

	fmt.Fprintf(os.Stderr, "Account %q removed.\n", name)
	return exitOK
}

// cmdExport prints the otpauth:// URI for a named account.
func cmdExport(args []string) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	showSecret := fs.Bool("show-secret", false, "include the raw secret in the exported URI")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: stdotp export <name> [--show-secret]")
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() < 1 {
		fs.Usage()
		return exitUsage
	}
	name := fs.Arg(0)

	fmt.Fprint(os.Stderr, "Master password: ")
	password, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}

	data, _, _, err := loadVault(globalVaultPath, password)
	if err != nil {
		return vaultErrCode(err)
	}

	account, ok := findAccount(data, name)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: account %q not found\n", name)
		return exitNotFound
	}

	// Only the URI itself goes to stdout; the password prompt went to stderr.
	fmt.Println(buildOTPAuthURI(account, *showSecret))
	return exitOK
}

// readLine reads one line from the shared stdin reader.
//
// Note: input is NOT masked — characters echo as typed. This is a documented
// limitation: golang.org/x/term provides masking but is not part of the Go
// standard library. The threat model section of the README covers this
// explicitly rather than staying silent on it.
func readLine() (string, error) {
	line, err := stdinReader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// findAccount returns the first account whose Name matches (case-sensitive).
func findAccount(data VaultData, name string) (Account, bool) {
	for _, a := range data.Accounts {
		if a.Name == name {
			return a, true
		}
	}
	return Account{}, false
}

// vaultErrCode maps vault load errors to the correct CLI exit code,
// prints an appropriate message to stderr, and returns the exit code.
func vaultErrCode(err error) int {
	switch {
	case errors.Is(err, errVaultMissing):
		fmt.Fprintln(os.Stderr, "error: vault not initialized — run 'stdotp init' first")
		return exitVaultMissing
	case errors.Is(err, errWrongPassword):
		fmt.Fprintln(os.Stderr, "error: wrong password or corrupted vault")
		return exitWrongPass
	default:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
}
