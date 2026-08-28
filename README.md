# stdotp

A zero-dependency CLI TOTP/HOTP authenticator with an **AES-256-GCM encrypted vault**.
Built for **Zero Dependency 2026 · Track E: Security & Crypto Utilities**.

Every cryptographic choice is documented and defensible; every dependency is replaced with
a standard-library equivalent.

---

## Quick start

`sh
go build -o stdotp .
./stdotp init
./stdotp add myaccount          # prompts for base32 secret or otpauth:// URI on stdin
./stdotp code myaccount
`

## Features

| Feature | Detail |
|---|---|
| **TOTP / HOTP** | RFC 6238 / RFC 4226, SHA-1 / SHA-256 / SHA-512 |
| **Vault encryption** | AES-256-GCM, PBKDF2-HMAC-SHA256 KDF (600,000 iterations) |
| **Atomic writes** | temp file → sync → os.Rename — crash-safe |
| **otpauth:// interop** | import from and export to Google Authenticator |
| **Air-gapped** | zero network calls; verified with no internet connection |
| **Zero runtime deps** | only the Go standard library; empty equire block in go.mod |
| **Extensive Test Suite** | 26 automated tests (RFC vectors + CLI integration, 76.2% coverage) |

---

## Build

`sh
go build -o stdotp .
`

### Reproducible build

`sh
CGO_ENABLED=0 go build -trimpath -ldflags="-buildid=" -o stdotp .
sha256sum stdotp     # or Get-FileHash on Windows
`

Build twice in separate directories — the SHA-256 hashes must match.
See [Reproducible Build Proof](#reproducible-build-proof) below for confirmed hashes.

---

## Usage

`
stdotp [--vault <path>] <subcommand> [options]

Subcommands:
  init                       Initialize a new encrypted vault
  add <name>                 Add an account (interactive: prompts on stdin)
    --secret-file <path>     Read base32 secret from a file  (preferred)
    --uri-file <path>        Read otpauth:// URI from a file  (preferred)
    --secret <base32>        Provide secret directly  (shell-history risk)
    --uri <otpauth://...>    Provide URI directly      (shell-history risk)
  code <name>                Generate the current TOTP/HOTP code
    --json                   Output as JSON
  list                       List all accounts
  remove <name>              Remove an account
  export <name>              Print otpauth:// URI for an account
    --show-secret            Include the raw secret in the URI

Global flag:
  --vault <path>             Vault file path (default: ~/.stdotp/vault.json)

Exit codes:  0 ok  1 error  2 usage  3 wrong password  4 not found  5 vault missing
`

### Demo transcript

`sh
$ ./stdotp init
Enter new master password:
Confirm master password:
Vault initialized at /home/user/.stdotp/vault.json

$ ./stdotp add github
Master password:
Enter base32 secret or otpauth:// URI:
Account "github" added.

$ ./stdotp list
Master password:
NAME    ISSUER  TYPE  ALGO  DIGITS  PERIOD
github  -       TOTP  SHA1  6       30

$ ./stdotp code github
Master password:
428157  (12s remaining)

$ ./stdotp code github --json
Master password:
{"account":"github","code":"428157","seconds_remaining":12}

$ ./stdotp export github
Master password:
otpauth://totp/github?secret=%5BREDACTED%5D

$ ./stdotp export github --show-secret
Master password:
otpauth://totp/github?secret=JBSWY3DPEHPK3PXP

$ ./stdotp remove github
Master password:
Account "github" removed.
`

---

## Threat model

### Vault encryption

The vault is an AES-256-GCM encrypted JSON envelope. Every field is documented in
plaintext so the format can be understood without reverse-engineering a binary:

`json
{
  "format_version": 1,
  "kdf": "PBKDF2-HMAC-SHA256",
  "kdf_iterations": 600000,
  "kdf_salt": "<base64, 16 random bytes from crypto/rand>",
  "nonce": "<base64, 12 random bytes from crypto/rand, fresh every write>",
  "ciphertext": "<base64, AES-256-GCM output — auth tag rides inside>"
}
`

**Key derivation:** PBKDF2-HMAC-SHA256 implemented exactly per RFC 2898 §5.2 by
composing crypto/hmac. Not a custom algorithm — a faithful standard construction
built entirely from stdlib primitives.

**Iteration count:** 600,000 (OWASP Password Storage Cheat Sheet 2026 recommendation
for PBKDF2-HMAC-SHA256, benchmarked against modern GPU hardware).

**Nonce:** freshly generated from crypto/rand on every vault write. Reusing a nonce
with the same key breaks GCM's security guarantee; this is enforced as a hard rule
in encryptVault.

### Fail-safe behaviour

These are named, tested properties — not implementation accidents:

| Situation | Behaviour |
|---|---|
| Wrong password or tampered ciphertext | AES-GCM auth check fails → exit 3, never partial plaintext |
| Corrupted / unreadable vault | Hard refuse → exit 1, never attempt silent repair |
| Missing vault file | Hard refuse → exit 5, never silently auto-create |
| Crash mid-write | Temp file + sync + os.Rename — previous vault always intact |

### Secret input security

--secret and --uri land in shell history and ps output.
The interactive stdin path (or --secret-file / --uri-file) keeps secrets out of
both. The README and the demo video show the interactive path; the inline flags exist
only for scripting convenience.

### Known limitations

- **No password masking:** golang.org/x/term provides masking but is not part of the
  Go standard library and cannot be imported without breaking the zero-dependency
  requirement. Password characters echo to the terminal as typed.
- **Memory hygiene:** RFC 7914 §14 notes that passwords and derived key material can
  linger in process memory, core dumps, and swap after use. stdotp does not lock or
  zero memory pages — Go's garbage collector makes that hard to guarantee reliably.
  This is a known limitation, not a hidden one.

### Air-gap verification

All six subcommands (init, dd, code, list, emove, export) operate with
no network calls. Verified by running with network access blocked on Windows and Linux
— every command completes normally.

---

## Test suite & Code coverage

Run the full test suite with coverage:

`sh
go test -v -cover .
`

### Test coverage summary:
- **Statement coverage**: **76.2%** of statements in stdotp.go
- **Total automated tests**: **26 tests** (0 failures)

| Test Group | Tests | Description |
|---|---|---|
| **HOTP Primitives** | TestHOTP_RFC4226, TestHOTP_PaddedOutput | RFC 4226 Appendix D vectors (10 cases) & padding |
| **TOTP Primitives** | TestTOTP_RFC6238, TestTOTP_SecondsRemaining | RFC 6238 Appendix B vectors across SHA1/256/512 (18 cases) |
| **PBKDF2 KDF** | TestPBKDF2_RFC7914 | RFC 7914 §11 official test vectors (c=1, c=80000) |
| **Vault Crypto** | TestVaultEncryptDecrypt, TestVaultTamperedCiphertext, TestVaultWrongKey | AES-256-GCM encryption, fresh nonce enforcement, tamper rejection |
| **Vault Storage** | TestSaveLoadVault, TestLoadVault_WrongPassword, TestLoadVault_Missing | Atomic file writes, crash resilience, exit code mapping |
| **URI & Encoding** | TestParseOTPAuthURI_Valid, TestParseOTPAuthURI_Invalid, TestBuildOTPAuthURI_*, TestDecodeSecret_* | Google Authenticator URI parsing, secret redaction, Base32 edge cases |
| **CLI Workflows** | TestCLI_FullWorkflow, TestCLI_WrongPassword, TestCLI_VaultMissing, TestCLI_AccountNotFound, TestCLI_DuplicateAccount, TestCLI_AddViaURI, TestCLI_StdoutStderrSplit | Complete integration tests simulating real command invocations |

---

## Package killer

stdotp eliminates the need for:

| Eliminated package | Replaced with |
|---|---|
| github.com/pquerna/otp | crypto/hmac + crypto/sha1/256/512 + encoding/base32 (full RFC 4226/6238) |
| golang.org/x/crypto/pbkdf2 | hand-rolled PBKDF2 loop over crypto/hmac (RFC 2898 §5.2) |
| github.com/spf13/cobra | lag + manual subcommand dispatch |
| github.com/stretchr/testify | plain 	esting |
| golang.org/x/term | documented limitation (no masked input) |
| gopkg.in/yaml.v3 | encoding/json for vault format |
| github.com/mattn/go-sqlite3 | flat encrypted file via os + encoding/json |
| github.com/olekukonko/tablewriter | 	ext/tabwriter |
| github.com/pkg/errors | errors + mt.Errorf("...: %w", err) |
| github.com/google/uuid | crypto/rand + manual hex |
| github.com/fatih/color | raw ANSI or plain output |
| github.com/joho/godotenv | os.Getenv directly |

See [STDLIB.md](STDLIB.md) for the full table.

---

## Dependency proof

`
$ go list -m all
stdotp

$ GOPROXY=off go build ./...
(no output — build succeeds with zero external dependencies)
`

---

## Reproducible build proof

Build command:
`sh
CGO_ENABLED=0 go build -trimpath -ldflags="-buildid=" -o stdotp .
`

| Build | SHA-256 |
|---|---|
| Build 1 | 0DC02EF65B08A38421134687676A9D377D3746259F33151B56ABCEC8B32BC43D |
| Build 2 | 0DC02EF65B08A38421134687676A9D377D3746259F33151B56ABCEC8B32BC43D |

Go version: go1.27.0 windows/amd64

---

## References

- M'Raihi, D., et al., "HOTP: An HMAC-Based One-Time Password Algorithm," RFC 4226, December 2005.
- M'Raihi, D., et al., "TOTP: Time-Based One-Time Password Algorithm," RFC 6238, May 2011.
- Kaliski, B., "PKCS #5: Password-Based Cryptography Specification Version 2.0," RFC 2898, September 2000.
- Percival, C. and Josefsson, S., "The scrypt Password-Based Key Derivation Function," RFC 7914, Section 11, August 2016.
- Josefsson, S., "The Base16, Base32, and Base64 Data Encodings," RFC 4648, October 2006.

---

## License

MIT — see [LICENSE](LICENSE).
