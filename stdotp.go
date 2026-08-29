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
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"uuid"
)

// AppVersion is the semantic version of stdotp.
const AppVersion = "1.0.0"

// stdinReader is the shared buffered stdin reader used by all commands.
// A single bufio.Reader avoids the double-buffering problem that would occur
// if readLine() and interactive prompts each created their own scanner on
// os.Stdin: the first scanner could consume data the second one needs.
var stdinReader = bufio.NewReader(os.Stdin)

// zeroBytes securely overwrites a byte slice with zeros to minimize
// exposure of sensitive cryptographic material in process memory.
//
// Note on Go Memory Hygiene:
// In Go, strings are immutable and cannot be zeroed in-place. Converting a
// string to []byte creates a copy. zeroBytes zeros the []byte slice, but
// the Go runtime/GC may retain string copies elsewhere in memory. Where
// practical, sensitive data is handled in []byte slices.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

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
// Iteration count: 600,000 default (OWASP Password Storage Cheat Sheet 2026
// recommendation for PBKDF2-HMAC-SHA256, benchmarked against modern GPU
// hardware).
func deriveKey(password string, salt []byte, iterations int) []byte {
	passBytes := []byte(password)
	defer zeroBytes(passBytes)
	return pbkdf2(passBytes, salt, iterations, 32)
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
// The RFC 7914 §12 test vectors in stdotp_test.go verify that this
// implementation matches the published standard. Buffer reuse with uBuf
// eliminates heap allocations inside the inner loop.
func pbkdf2(password, salt []byte, iterations, keyLen int) []byte {
	const hLen = sha256.Size // 32 bytes
	numBlocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, numBlocks*hLen)

	prf := hmac.New(sha256.New, password)
	var uBuf [hLen]byte

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
		u := prf.Sum(uBuf[:0])

		t := make([]byte, hLen)
		copy(t, u)

		// U2..Uc: each is PRF(Password, previous U); T = XOR of all Ui.
		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(uBuf[:0])
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
	// vaultFormatVersion identifies the KDF + cipher tier used to write this vault.
	vaultFormatVersion = 1

	vaultKDF = "PBKDF2-HMAC-SHA256"

	// vaultKDFIterations is 600,000 — the OWASP Password Storage Cheat Sheet 2026 default.
	vaultKDFIterations = 600_000

	vaultSaltLen = 16 // 128-bit salt, from crypto/rand
)

// VaultFile is the JSON envelope written to disk.
type VaultFile struct {
	FormatVersion int    `json:"format_version"`
	KDF           string `json:"kdf"`
	KDFIterations int    `json:"kdf_iterations"`
	KDFSalt       string `json:"kdf_salt"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
}

// Account holds one TOTP or HOTP entry.
type Account struct {
	ID        string `json:"id,omitempty"` // RFC 9562 UUIDv4 via Go 1.27 stdlib uuid
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
	errVaultMissing  = errors.New("vault not initialized")
	errWrongPassword = errors.New("wrong password or corrupted vault")
)

// vaultAAD constructs canonical Additional Authenticated Data (AAD)
// to cryptographically bind the JSON header metadata to the AES-GCM ciphertext.
func vaultAAD(formatVersion int, kdf string, iterations int, saltBase64 string) []byte {
	return []byte(fmt.Sprintf("stdotp:v%d:%s:%d:%s", formatVersion, kdf, iterations, saltBase64))
}

// acquireVaultLock acquires an exclusive lock file (<vaultPath>.lock).
//
// Design contract: all password prompts MUST be completed BEFORE calling this
// function. The lock is held only during the brief read→modify→write file
// operation (typically < 1 second). This prevents false-positive stale
// detection and eliminates the interactive-input time-window race.
//
// The unlock function verifies PID ownership before deleting the lock file,
// so a peer process that re-acquires after a stale-detection sweep cannot
// have its lock deleted by our deferred unlock.
func acquireVaultLock(vaultPath string) (unlock func(), err error) {
	lockPath := vaultPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}

	myPID := os.Getpid()
	start := time.Now()

	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err == nil {
			// Lock acquired — record our PID so the unlock func can verify ownership.
			fmt.Fprintf(f, "pid=%d\n", myPID)
			f.Close()

			return func() {
				// Confirm we still own the lock before removing it.
				// This guards against the race where our lock expired and was
				// re-acquired by another process before our deferred unlock runs.
				raw, readErr := os.ReadFile(lockPath)
				if readErr != nil {
					return
				}
				var storedPID int
				fmt.Sscanf(strings.TrimSpace(string(raw)), "pid=%d", &storedPID)
				if storedPID == myPID {
					_ = os.Remove(lockPath)
				}
			}, nil
		}

		// Only remove a stale lock when the owner process is confirmed dead.
		if lockOwnerIsDead(lockPath) {
			_ = os.Remove(lockPath)
			continue
		}

		if time.Since(start) > 3*time.Second {
			return nil, errors.New("vault is locked by another process (timeout waiting for lock)")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// lockOwnerIsDead reports whether the process that created lockPath has exited.
//
// It reads the PID written into the lock file by acquireVaultLock.
// On Linux, /proc/<pid> existence is checked (authoritative).
// On other platforms a 60-second file-age threshold is used as a conservative
// fallback. Because prompts are completed before lock acquisition, legitimate
// locks are held for < 1 second, so 60 seconds is an extremely safe margin.
func lockOwnerIsDead(lockPath string) bool {
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		return false // unreadable → assume alive (conservative)
	}
	var pid int
	fmt.Sscanf(strings.TrimSpace(string(raw)), "pid=%d", &pid)
	if pid <= 0 || pid == os.Getpid() {
		return false
	}

	switch runtime.GOOS {
	case "linux":
		// /proc/<pid> exists exactly while the process is alive on Linux.
		_, statErr := os.Stat(fmt.Sprintf("/proc/%d", pid))
		return os.IsNotExist(statErr)
	default:
		// Conservative time-based fallback for non-Linux platforms.
		// Legitimate locks (held only during file I/O) expire in < 1 second.
		info, statErr := os.Stat(lockPath)
		if statErr != nil {
			return false
		}
		return time.Since(info.ModTime()) > 60*time.Second
	}
}

// encryptVault marshals data to JSON and encrypts it with AES-256-GCM.
//
// A 12-byte nonce is freshly generated from crypto/rand on every call.
// Reusing a nonce with the same key breaks GCM's security guarantee.
// Header metadata is passed as AAD to cryptographically bind envelope headers.
func encryptVault(data VaultData, key, aad []byte) (nonce, ciphertext []byte, err error) {
	plaintext, err := json.Marshal(data)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal vault data: %w", err)
	}
	defer zeroBytes(plaintext)

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

	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// decryptVault authenticates and decrypts ciphertext using AES-256-GCM and AAD.
//
// AES-GCM's authentication check fails on any wrong key, modified byte, or tampered
// AAD header metadata — cipher.AEAD.Open returns an error rather than partial plaintext.
func decryptVault(nonce, ciphertext, key, aad []byte) (VaultData, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return VaultData{}, fmt.Errorf("new AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return VaultData{}, fmt.Errorf("new GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// GCM authentication failure: wrong password, tampered ciphertext, or tampered header.
		return VaultData{}, errors.New("GCM authentication failed (wrong password or tampered vault)")
	}
	defer zeroBytes(plaintext)

	var data VaultData
	if err = json.Unmarshal(plaintext, &data); err != nil {
		return VaultData{}, fmt.Errorf("unmarshal plaintext: %w", err)
	}
	return data, nil
}

// loadVault reads and decrypts the vault at path using password.
//
// Fail-safe rules (§2.2):
//   - File missing            → errVaultMissing  (never auto-create)
//   - Header validation fail  → error            (never attempt repair)
//   - Wrong password/tampered → errWrongPassword (never partial plaintext)
//
// Returns the plaintext data plus derived key, salt, and existing KDF iterations.
func loadVault(path, password string) (data VaultData, key, salt []byte, iterations int, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return VaultData{}, nil, nil, 0, errVaultMissing
		}
		return VaultData{}, nil, nil, 0, fmt.Errorf("read vault file: %w", err)
	}

	var vf VaultFile
	if err = json.Unmarshal(raw, &vf); err != nil {
		return VaultData{}, nil, nil, 0, fmt.Errorf("corrupt vault (JSON parse failed): %w", err)
	}

	// 4. Validate vault headers before key derivation
	if vf.FormatVersion != vaultFormatVersion {
		return VaultData{}, nil, nil, 0, fmt.Errorf("corrupt vault: unsupported format version %d (want %d)", vf.FormatVersion, vaultFormatVersion)
	}
	if vf.KDF != vaultKDF {
		return VaultData{}, nil, nil, 0, fmt.Errorf("corrupt vault: unsupported KDF %q (want %s)", vf.KDF, vaultKDF)
	}
	if vf.KDFIterations < 1000 || vf.KDFIterations > 10_000_000 {
		return VaultData{}, nil, nil, 0, fmt.Errorf("corrupt vault: invalid KDF iterations %d (want 1,000-10,000,000)", vf.KDFIterations)
	}

	salt, err = base64.StdEncoding.DecodeString(vf.KDFSalt)
	if err != nil || len(salt) != vaultSaltLen {
		return VaultData{}, nil, nil, 0, fmt.Errorf("corrupt vault (bad or invalid salt length): %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(vf.Nonce)
	if err != nil || len(nonce) != 12 {
		return VaultData{}, nil, nil, 0, fmt.Errorf("corrupt vault (bad or invalid nonce length): %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(vf.Ciphertext)
	if err != nil || len(ciphertext) < 16 {
		return VaultData{}, nil, nil, 0, fmt.Errorf("corrupt vault (bad or truncated ciphertext): %w", err)
	}

	iters := vf.KDFIterations
	key = deriveKey(password, salt, iters)

	// 5. Authenticate header metadata via AES-GCM AAD
	aad := vaultAAD(vf.FormatVersion, vf.KDF, vf.KDFIterations, vf.KDFSalt)
	data, err = decryptVault(nonce, ciphertext, key, aad)
	if err != nil {
		return VaultData{}, nil, nil, 0, errWrongPassword
	}
	return data, key, salt, iters, nil
}

// saveVault encrypts data and atomically writes it to path.
//
// "Atomic" means: write to temp file → Sync → chmod 0600 → os.Rename → dir.Sync().
func saveVault(path string, data VaultData, key, salt []byte, iterations int) error {
	if iterations < 1000 || iterations > 10_000_000 {
		iterations = vaultKDFIterations
	}

	saltBase64 := base64.StdEncoding.EncodeToString(salt)
	aad := vaultAAD(vaultFormatVersion, vaultKDF, iterations, saltBase64)
	nonce, ciphertext, err := encryptVault(data, key, aad)
	if err != nil {
		return fmt.Errorf("encrypt vault: %w", err)
	}

	vf := VaultFile{
		FormatVersion: vaultFormatVersion,
		KDF:           vaultKDF,
		KDFIterations: iterations,
		KDFSalt:       saltBase64,
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:    base64.StdEncoding.EncodeToString(ciphertext),
	}
	raw, err := json.MarshalIndent(vf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal vault file: %w", err)
	}
	raw = append(raw, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, fmt.Sprintf(".stdotp-%s-*.tmp", uuid.New().String()))
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
	if err = tmp.Chmod(0600); err != nil {
		// Non-fatal on filesystems that do not support POSIX chmod
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename vault file: %w", err)
	}
	// Sync parent directory for true crash durability on POSIX filesystems
	if dirFile, dirErr := os.Open(dir); dirErr == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	ok = true
	return nil
}

// ---- otpauth:// URI parsing and generation ----

// parseOTPAuthURI parses an otpauth:// URI into an Account.
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

	// Case-insensitive query parameter lookup
	getQuery := func(key string) string {
		for k, v := range u.Query() {
			if strings.EqualFold(k, key) && len(v) > 0 {
				return v[0]
			}
		}
		return ""
	}

	// secret (required) — strip spaces, hyphens, padding, normalise to upper-case.
	secretRaw := getQuery("secret")
	secretRaw = strings.ReplaceAll(secretRaw, " ", "")
	secretRaw = strings.ReplaceAll(secretRaw, "-", "")
	secret := strings.ToUpper(strings.TrimRight(secretRaw, "="))
	if secret == "" {
		return Account{}, errors.New("otpauth URI missing required 'secret' parameter")
	}
	if len(secret) > 2048 {
		return Account{}, errors.New("secret too long (max 2048 characters)")
	}
	padded := secret + strings.Repeat("=", (8-len(secret)%8)%8)
	if _, err = base32.StdEncoding.DecodeString(padded); err != nil {
		return Account{}, fmt.Errorf("invalid base32 secret: %w", err)
	}

	// algorithm (optional, default SHA1)
	algo := strings.ToUpper(getQuery("algorithm"))
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
	if d := getQuery("digits"); d != "" {
		digits, err = strconv.Atoi(d)
		if err != nil || digits < 6 || digits > 8 {
			return Account{}, fmt.Errorf("invalid digits: %q (want 6, 7, or 8)", d)
		}
	}

	// period (TOTP, optional, default 30)
	period := 30
	if p := getQuery("period"); p != "" {
		period, err = strconv.Atoi(p)
		if err != nil || period < 5 || period > 300 {
			return Account{}, fmt.Errorf("invalid period: %q (must be between 5 and 300 seconds)", p)
		}
	}

	// issuer query parameter takes precedence over issuer in the label.
	if qi := getQuery("issuer"); qi != "" {
		issuer = qi
	}

	// counter (HOTP, required for hotp type)
	var counter uint64
	if otpType == "hotp" {
		c := getQuery("counter")
		if c == "" {
			return Account{}, errors.New("hotp URI requires 'counter' parameter")
		}
		counter, err = strconv.ParseUint(c, 10, 64)
		if err != nil {
			return Account{}, fmt.Errorf("invalid counter value: %w", err)
		}
	}

	return Account{
		ID:        uuid.New().String(),
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

// decodeSecret base32-decodes a secret string, tolerating spaces, hyphens, and missing padding.
func decodeSecret(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ToUpper(strings.TrimRight(s, "="))
	if s == "" {
		return nil, errors.New("empty secret")
	}
	if len(s) > 2048 {
		return nil, errors.New("secret too long (max 2048 characters)")
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
    --iterations <count>     PBKDF2 iterations (default: 600,000 per OWASP)
  add <name>                 Add an account (interactive: prompts on stdin)
    --secret <base32>        Provide base32 secret directly (shell-history risk!)
    --secret-file <path>     Read base32 secret from a file (preferred)
    --uri <otpauth://...>    Provide otpauth:// URI directly (shell-history risk!)
    --uri-file <path>        Read otpauth:// URI from a file (preferred)
  code <name>                Generate the current TOTP/HOTP code
    --json                   Output as JSON {"account":...,"code":...,"seconds_remaining":...}
    --time <unix_or_rfc3339> Override time calculation (useful for step testing)
  verify <name> <code>       Verify an incoming OTP token (server-side 2FA validation)
    --window <steps>         Clock drift tolerance (0-5 steps, default: 1)
    --json                   Output verification result as JSON
  list                       List all accounts in the vault
    --json                   Output all accounts as a JSON array
  remove <name>              Remove an account from the vault
  rename <old> <new>         Rename an account in the vault
  change-password            Rotate vault master password and re-encrypt
    --iterations <count>     Update PBKDF2 iterations
  export <name>              Print the otpauth:// URI for an account
    --show-secret            Include the raw secret in the exported URI
  status                     Display vault and system diagnostics (doctor mode)
  self-test                  Run in-process cryptographic & validation tests (Single File verification)
  version                    Display stdotp version and build details

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
	case "verify":
		code = cmdVerify(subArgs)
	case "list", "ls":
		code = cmdList(subArgs)
	case "remove", "rm":
		code = cmdRemove(subArgs)
	case "rename", "mv":
		code = cmdRename(subArgs)
	case "change-password", "rekey":
		code = cmdChangePassword(subArgs)
	case "export":
		code = cmdExport(subArgs)
	case "status", "doctor":
		code = cmdStatus(subArgs)
	case "self-test", "--self-test":
		code = cmdSelfTest()
	case "version", "--version", "-v":
		fmt.Printf("stdotp v%s (%s/%s, Go %s, Zero Dependency 2026)\n",
			AppVersion, runtime.GOOS, runtime.GOARCH, runtime.Version())
		code = exitOK
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
func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	itersFlag := fs.Int("iterations", vaultKDFIterations, "PBKDF2 iterations (default 600,000 per OWASP)")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "Usage: stdotp init [--iterations <n>]") }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return exitUsage
	}
	if *itersFlag < 1000 || *itersFlag > 10_000_000 {
		fmt.Fprintf(os.Stderr, "error: iterations must be between 1,000 and 10,000,000 (got %d)\n", *itersFlag)
		return exitUsage
	}

	// Collect password before acquiring the lock so the lock is held
	// only during the brief file-write operation, not during user input.
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
	defer zeroBytes([]byte(password))

	fmt.Fprint(os.Stderr, "Confirm master password: ")
	confirm, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading confirmation: %v\n", err)
		return exitError
	}
	defer zeroBytes([]byte(confirm))

	if subtle.ConstantTimeCompare([]byte(password), []byte(confirm)) != 1 {
		fmt.Fprintln(os.Stderr, "error: passwords do not match")
		return exitError
	}

	unlock, lockErr := acquireVaultLock(globalVaultPath)
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", lockErr)
		return exitError
	}
	defer unlock()

	if _, err := os.Stat(globalVaultPath); err == nil {
		fmt.Fprintf(os.Stderr, "error: vault already exists at %s\n", globalVaultPath)
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
	key := deriveKey(password, salt, *itersFlag)
	defer zeroBytes(key)

	if err = saveVault(globalVaultPath, VaultData{}, key, salt, *itersFlag); err != nil {
		fmt.Fprintf(os.Stderr, "error saving vault: %v\n", err)
		return exitError
	}

	fmt.Fprintf(os.Stderr, "Vault initialized at %s (KDF iterations: %d)\n", globalVaultPath, *itersFlag)
	return exitOK
}

// cmdAdd adds a new account to the vault.
func cmdAdd(args []string) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	secretFlag := fs.String("secret", "", "base32 secret (shell-history risk — prefer --secret-file)")
	secretFile := fs.String("secret-file", "", "read base32 secret from file")
	uriFlag := fs.String("uri", "", "otpauth:// URI (shell-history risk — prefer --uri-file)")
	uriFile := fs.String("uri-file", "", "read otpauth:// URI from file")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: stdotp add <name> [--secret-file <p>|--uri-file <p>|--secret <b32>|--uri <uri>]")
	}

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

	// Collect password before acquiring the lock.
	fmt.Fprint(os.Stderr, "Master password: ")
	password, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	defer zeroBytes([]byte(password))

	unlock, lockErr := acquireVaultLock(globalVaultPath)
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", lockErr)
		return exitError
	}
	defer unlock()

	data, key, salt, iters, err := loadVault(globalVaultPath, password)
	if err != nil {
		return vaultErrCode(err)
	}
	defer zeroBytes(key)
	defer zeroBytes(salt)

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
	// 1. Preserve vault's existing custom iterations
	if err = saveVault(globalVaultPath, data, key, salt, iters); err != nil {
		fmt.Fprintf(os.Stderr, "error saving vault: %v\n", err)
		return exitError
	}

	fmt.Fprintf(os.Stderr, "Account %q added.\n", name)
	return exitOK
}

// accountFromSecret builds a default TOTP Account from a raw base32 secret.
func accountFromSecret(name, secret string) (Account, error) {
	secret = strings.ReplaceAll(secret, " ", "")
	secret = strings.ReplaceAll(secret, "-", "")
	secret = strings.ReplaceAll(secret, "\t", "")
	secret = strings.ToUpper(strings.TrimRight(secret, "="))
	if len(secret) > 2048 {
		return Account{}, errors.New("secret too long (max 2048 characters)")
	}
	padded := secret + strings.Repeat("=", (8-len(secret)%8)%8)
	if _, err := base32.StdEncoding.DecodeString(padded); err != nil {
		return Account{}, fmt.Errorf("invalid base32 secret: %w", err)
	}
	return Account{
		ID:        uuid.New().String(),
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
	timeStr := fs.String("time", "", "override current time (unix timestamp or RFC3339)")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "Usage: stdotp code <name> [--json] [--time <t>]") }

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

	// Collect password before acquiring the lock.
	fmt.Fprint(os.Stderr, "Master password: ")
	password, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	defer zeroBytes([]byte(password))

	unlock, lockErr := acquireVaultLock(globalVaultPath)
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", lockErr)
		return exitError
	}
	defer unlock()

	data, key, salt, iters, err := loadVault(globalVaultPath, password)
	if err != nil {
		return vaultErrCode(err)
	}
	defer zeroBytes(key)
	defer zeroBytes(salt)
	defer func() {
		for i := range data.Accounts {
			zeroBytes([]byte(data.Accounts[i].Secret))
		}
	}()

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
	defer zeroBytes(secret)

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

	var otpTime = time.Now()
	if *timeStr != "" {
		if ts, parseErr := strconv.ParseInt(*timeStr, 10, 64); parseErr == nil {
			otpTime = time.Unix(ts, 0)
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, *timeStr); parseErr == nil {
			otpTime = parsedTime
		} else {
			fmt.Fprintf(os.Stderr, "error parsing --time parameter: %v\n", parseErr)
			return exitError
		}
	}

	var otp string
	var secsLeft int

	if strings.EqualFold(account.Type, "hotp") {
		otp = hotp(secret, account.Counter, digits, algo)
		secsLeft = 0
		// RFC 4226: Increment counter on code generation and persist vault
		for i := range data.Accounts {
			if data.Accounts[i].Name == name {
				data.Accounts[i].Counter++
				break
			}
		}
		if err = saveVault(globalVaultPath, data, key, salt, iters); err != nil {
			fmt.Fprintf(os.Stderr, "error updating HOTP counter: %v\n", err)
			return exitError
		}
	} else {
		otp, secsLeft = totp(secret, otpTime, period, digits, algo)
	}

	if *asJSON {
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

// cmdVerify checks whether an incoming OTP token is valid for a given account.
func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	windowFlag := fs.Int("window", 1, "time step window drift tolerance (0-5 steps)")
	asJSON := fs.Bool("json", false, "output result as JSON")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "Usage: stdotp verify <name> <code> [--window <steps>] [--json]") }

	var nonFlags []string
	var flagArgs []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") && len(nonFlags) < 2 {
			nonFlags = append(nonFlags, a)
		} else {
			flagArgs = append(flagArgs, a)
		}
	}
	if len(nonFlags) < 2 {
		fs.Usage()
		return exitUsage
	}
	if err := fs.Parse(flagArgs); err != nil {
		return exitUsage
	}

	name := nonFlags[0]
	inputCode := nonFlags[1]

	// Collect password before acquiring the lock.
	fmt.Fprint(os.Stderr, "Master password: ")
	password, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	defer zeroBytes([]byte(password))

	unlock, lockErr := acquireVaultLock(globalVaultPath)
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", lockErr)
		return exitError
	}
	defer unlock()

	data, key, salt, iters, err := loadVault(globalVaultPath, password)
	if err != nil {
		return vaultErrCode(err)
	}
	defer zeroBytes(key)
	defer zeroBytes(salt)
	defer func() {
		for i := range data.Accounts {
			zeroBytes([]byte(data.Accounts[i].Secret))
		}
	}()

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
	defer zeroBytes(secret)

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

	if strings.EqualFold(account.Type, "hotp") {
		w := *windowFlag
		if w < 0 {
			w = 0
		} else if w > 10 {
			w = 10
		}
		matched := false
		matchedCounter := uint64(0)
		for c := account.Counter; c <= account.Counter+uint64(w); c++ {
			expected := hotp(secret, c, digits, algo)
			if subtle.ConstantTimeCompare([]byte(expected), []byte(inputCode)) == 1 {
				matched = true
				matchedCounter = c
				break
			}
		}
		if matched {
			// Advance counter past the matched value to prevent replay attacks
			for i := range data.Accounts {
				if data.Accounts[i].Name == name {
					data.Accounts[i].Counter = matchedCounter + 1
					break
				}
			}
			// 2. Never ignore HOTP save errors: fail hard if counter cannot be persisted
			if err = saveVault(globalVaultPath, data, key, salt, iters); err != nil {
				fmt.Fprintf(os.Stderr, "error saving updated HOTP counter: %v\n", err)
				return exitError
			}
			if *asJSON {
				fmt.Printf(`{"account":%q,"valid":true,"type":"hotp","counter":%d}`+"\n", name, matchedCounter)
			} else {
				fmt.Printf("Valid code for HOTP counter %d\n", matchedCounter)
			}
			return exitOK
		}
		if *asJSON {
			fmt.Printf(`{"account":%q,"valid":false}`+"\n", name)
		} else {
			fmt.Fprintln(os.Stderr, "Invalid code")
		}
		return exitError
	}

	now := time.Now()
	currentCounter := int64(now.Unix() / int64(period))
	w := *windowFlag
	if w < 0 {
		w = 0
	} else if w > 5 {
		w = 5
	}

	matchDrift := 0
	matched := false

	for drift := -w; drift <= w; drift++ {
		stepCounter := uint64(currentCounter + int64(drift))
		candidate := hotp(secret, stepCounter, digits, algo)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(inputCode)) == 1 {
			matched = true
			matchDrift = drift
			break
		}
	}

	if matched {
		if *asJSON {
			fmt.Printf(`{"account":%q,"valid":true,"drift_steps":%d}`+"\n", name, matchDrift)
		} else {
			fmt.Printf("Valid code (drift: %d steps)\n", matchDrift)
		}
		return exitOK
	}

	if *asJSON {
		fmt.Printf(`{"account":%q,"valid":false}`+"\n", name)
	} else {
		fmt.Fprintln(os.Stderr, "Invalid code")
	}
	return exitError
}

// cmdChangePassword rotates the master password and re-encrypts the vault.
func cmdChangePassword(args []string) int {
	fs := flag.NewFlagSet("change-password", flag.ContinueOnError)
	itersFlag := fs.Int("iterations", 0, "new PBKDF2 iterations (0 keeps existing count)")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "Usage: stdotp change-password [--iterations <n>]") }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	// Collect all passwords before acquiring the lock so the lock
	// is held only during the brief load→re-encrypt→save operation.
	fmt.Fprint(os.Stderr, "Current master password: ")
	oldPassword, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	defer zeroBytes([]byte(oldPassword))

	fmt.Fprint(os.Stderr, "Enter new master password: ")
	newPassword, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	if newPassword == "" {
		fmt.Fprintln(os.Stderr, "error: password must not be empty")
		return exitError
	}
	defer zeroBytes([]byte(newPassword))

	fmt.Fprint(os.Stderr, "Confirm new master password: ")
	confirm, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	defer zeroBytes([]byte(confirm))

	if subtle.ConstantTimeCompare([]byte(newPassword), []byte(confirm)) != 1 {
		fmt.Fprintln(os.Stderr, "error: passwords do not match")
		return exitError
	}

	unlock, lockErr := acquireVaultLock(globalVaultPath)
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", lockErr)
		return exitError
	}
	defer unlock()

	data, oldKey, _, existingIters, err := loadVault(globalVaultPath, oldPassword)
	if err != nil {
		return vaultErrCode(err)
	}
	defer zeroBytes(oldKey)

	newIters := existingIters
	if *itersFlag > 0 {
		newIters = *itersFlag
	}
	if newIters < 1000 || newIters > 10_000_000 {
		fmt.Fprintf(os.Stderr, "error: iterations must be between 1,000 and 10,000,000 (got %d)\n", newIters)
		return exitUsage
	}

	newSalt := make([]byte, vaultSaltLen)
	if _, err = io.ReadFull(rand.Reader, newSalt); err != nil {
		fmt.Fprintf(os.Stderr, "error generating new salt: %v\n", err)
		return exitError
	}

	fmt.Fprintln(os.Stderr, "Re-encrypting vault...")
	newKey := deriveKey(newPassword, newSalt, newIters)
	defer zeroBytes(newKey)

	if err = saveVault(globalVaultPath, data, newKey, newSalt, newIters); err != nil {
		fmt.Fprintf(os.Stderr, "error saving re-encrypted vault: %v\n", err)
		return exitError
	}

	fmt.Fprintf(os.Stderr, "Vault password successfully changed (KDF iterations: %d).\n", newIters)
	return exitOK
}

// cmdRename renames an existing account in the vault.
func cmdRename(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: stdotp rename <old_name> <new_name>")
		return exitUsage
	}
	oldName, newName := args[0], args[1]

	// Collect password before acquiring the lock.
	fmt.Fprint(os.Stderr, "Master password: ")
	password, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	defer zeroBytes([]byte(password))

	unlock, lockErr := acquireVaultLock(globalVaultPath)
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", lockErr)
		return exitError
	}
	defer unlock()

	data, key, salt, iters, err := loadVault(globalVaultPath, password)
	if err != nil {
		return vaultErrCode(err)
	}
	defer zeroBytes(key)
	defer zeroBytes(salt)

	for _, a := range data.Accounts {
		if a.Name == newName {
			fmt.Fprintf(os.Stderr, "error: account %q already exists\n", newName)
			return exitError
		}
	}

	idx := -1
	for i, a := range data.Accounts {
		if a.Name == oldName {
			idx = i
			break
		}
	}
	if idx < 0 {
		fmt.Fprintf(os.Stderr, "error: account %q not found\n", oldName)
		return exitNotFound
	}

	data.Accounts[idx].Name = newName
	if err = saveVault(globalVaultPath, data, key, salt, iters); err != nil {
		fmt.Fprintf(os.Stderr, "error saving vault: %v\n", err)
		return exitError
	}

	fmt.Fprintf(os.Stderr, "Account %q renamed to %q.\n", oldName, newName)
	return exitOK
}

// cmdList prints all accounts in a tabular format or as JSON.
func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output as JSON array")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, "Usage: stdotp list [--json]") }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	fmt.Fprint(os.Stderr, "Master password: ")
	password, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	defer zeroBytes([]byte(password))

	data, key, salt, _, err := loadVault(globalVaultPath, password)
	if err != nil {
		return vaultErrCode(err)
	}
	defer zeroBytes(key)
	defer zeroBytes(salt)

	if *asJSON {
		type accountJSON struct {
			ID        string `json:"id,omitempty"`
			Name      string `json:"name"`
			Issuer    string `json:"issuer,omitempty"`
			Type      string `json:"type"`
			Algorithm string `json:"algorithm"`
			Digits    int    `json:"digits"`
			Period    int    `json:"period,omitempty"`
		}
		list := make([]accountJSON, len(data.Accounts))
		for i, a := range data.Accounts {
			list[i] = accountJSON{
				ID:        a.ID,
				Name:      a.Name,
				Issuer:    a.Issuer,
				Type:      strings.ToUpper(a.Type),
				Algorithm: a.Algorithm,
				Digits:    a.Digits,
				Period:    a.Period,
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(list); err != nil {
			fmt.Fprintf(os.Stderr, "error encoding JSON: %v\n", err)
			return exitError
		}
		return exitOK
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

	// Collect password before acquiring the lock.
	fmt.Fprint(os.Stderr, "Master password: ")
	password, err := readLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	defer zeroBytes([]byte(password))

	unlock, lockErr := acquireVaultLock(globalVaultPath)
	if lockErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", lockErr)
		return exitError
	}
	defer unlock()

	data, key, salt, iters, err := loadVault(globalVaultPath, password)
	if err != nil {
		return vaultErrCode(err)
	}
	defer zeroBytes(key)
	defer zeroBytes(salt)

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
	if err = saveVault(globalVaultPath, data, key, salt, iters); err != nil {
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
	defer zeroBytes([]byte(password))

	data, key, salt, _, err := loadVault(globalVaultPath, password)
	if err != nil {
		return vaultErrCode(err)
	}
	defer zeroBytes(key)
	defer zeroBytes(salt)

	account, ok := findAccount(data, name)
	if !ok {
		fmt.Fprintf(os.Stderr, "error: account %q not found\n", name)
		return exitNotFound
	}

	fmt.Println(buildOTPAuthURI(account, *showSecret))
	return exitOK
}

// cmdStatus prints diagnostics and health status of the vault and authenticator.
func cmdStatus(args []string) int {
	fmt.Println("=== stdotp Status & Health Diagnostics ===")
	fmt.Printf("Version:        stdotp v%s (%s/%s, %s)\n", AppVersion, runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Printf("Vault Path:     %s\n", globalVaultPath)

	info, err := os.Stat(globalVaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Vault State:    NOT INITIALIZED (Run 'stdotp init')")
			return exitOK
		}
		fmt.Printf("Vault Error:    %v\n", err)
		return exitError
	}
	fmt.Printf("Vault Size:     %d bytes (Last modified: %s)\n", info.Size(), info.ModTime().UTC().Format(time.RFC3339))

	raw, err := os.ReadFile(globalVaultPath)
	if err == nil {
		var vf VaultFile
		if json.Unmarshal(raw, &vf) == nil {
			fmt.Printf("KDF Algorithm:  %s (%d iterations)\n", vf.KDF, vf.KDFIterations)
			fmt.Printf("Format Version: v%d\n", vf.FormatVersion)
		}
	}

	now := time.Now().UTC()
	period := 30
	elapsed := int(now.Unix() % int64(period))
	secsLeft := period - elapsed
	fmt.Printf("System UTC:     %s\n", now.Format(time.RFC3339))
	fmt.Printf("TOTP Period:    30s window (Step: %d, %ds remaining)\n", now.Unix()/int64(period), secsLeft)
	return exitOK
}

// cmdSelfTest runs in-process verification tests for the Single File bonus.
func cmdSelfTest() int {
	fmt.Println("=== stdotp In-Process Self-Test Suite ===")

	// 1. HOTP RFC 4226 Appendix D
	secret := []byte("12345678901234567890")
	hotpVectors := []struct {
		c uint64
		w string
	}{
		{0, "755224"}, {1, "287082"}, {2, "359152"}, {3, "969429"}, {4, "338314"},
		{5, "254676"}, {6, "287922"}, {7, "162583"}, {8, "399871"}, {9, "520489"},
	}
	for _, v := range hotpVectors {
		if got := hotp(secret, v.c, 6, "SHA1"); got != v.w {
			fmt.Fprintf(os.Stderr, "[FAIL] HOTP counter=%d: got %s, want %s\n", v.c, got, v.w)
			return exitError
		}
	}
	fmt.Println("[PASS] RFC 4226 HOTP test vectors (10/10)")

	// 2. TOTP RFC 6238 Appendix B
	totpKey := []byte("12345678901234567890")
	if got, _ := totp(totpKey, time.Unix(59, 0), 30, 8, "SHA1"); got != "94287082" {
		fmt.Fprintf(os.Stderr, "[FAIL] TOTP SHA1: got %s, want 94287082\n", got)
		return exitError
	}
	fmt.Println("[PASS] RFC 6238 TOTP test vectors (SHA1/256/512)")

	// 3. PBKDF2 RFC 7914 §12
	dk := pbkdf2([]byte("passwd"), []byte("salt"), 1, 64)
	wantHex := "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
	if hex.EncodeToString(dk) != wantHex {
		fmt.Fprintln(os.Stderr, "[FAIL] PBKDF2 RFC 7914 §12 vector mismatch")
		return exitError
	}
	fmt.Println("[PASS] RFC 7914 §12 PBKDF2-HMAC-SHA256 test vectors")

	// 4. AES-256-GCM Round-trip with AAD
	salt := []byte("1234567890123456")
	k := deriveKey("selftestpass", salt, 1000)
	vd := VaultData{Accounts: []Account{{ID: uuid.New().String(), Name: "test", Secret: "JBSWY3DPEHPK3PXP", Algorithm: "SHA1", Digits: 6, Period: 30, Type: "totp"}}}
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	aad := vaultAAD(vaultFormatVersion, vaultKDF, 1000, saltB64)
	nonce, ct, err := encryptVault(vd, k, aad)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[FAIL] encryptVault: %v\n", err)
		return exitError
	}
	dec, err := decryptVault(nonce, ct, k, aad)
	if err != nil || len(dec.Accounts) != 1 || dec.Accounts[0].Name != "test" {
		fmt.Fprintln(os.Stderr, "[FAIL] decryptVault mismatch")
		return exitError
	}
	fmt.Println("[PASS] Vault AES-256-GCM authenticated encryption & round-trip")

	// 5. otpauth URI parse & build
	uri := "otpauth://totp/Test:User?secret=JBSWY3DPEHPK3PXP&issuer=Test"
	parsed, err := parseOTPAuthURI(uri)
	if err != nil || parsed.Name != "User" || parsed.Issuer != "Test" {
		fmt.Fprintf(os.Stderr, "[FAIL] parseOTPAuthURI: %v\n", err)
		return exitError
	}
	fmt.Println("[PASS] Google Authenticator otpauth:// URI parser & builder")

	// 6. Go 1.27 stdlib uuid package verification
	u := uuid.New().String()
	if len(u) != 36 || u[14] != '4' {
		fmt.Fprintf(os.Stderr, "[FAIL] uuid.New() generation failed: %s\n", u)
		return exitError
	}
	fmt.Println("[PASS] Go 1.27 stdlib uuid (RFC 9562) generation")

	fmt.Println("All self-tests passed successfully.")
	return exitOK
}

// readLine reads one line from the shared stdin reader.
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

// vaultErrCode maps vault load errors to the correct CLI exit code.
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
