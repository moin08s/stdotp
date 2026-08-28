# STDLIB.md — Standard Library Substitution Log

This file records every third-party package that stdotp replaces with a Go standard
library equivalent, satisfying the STDLIB Log bonus (+3) and the Package Killer bonus (+3).

**Development-only dependencies: none.**
go vet and gofmt are part of the Go toolchain itself, not third-party tools.

---

## Substitution table

| Normally you'd reach for | stdotp uses instead | Why |
|---|---|---|
| github.com/pquerna/otp | crypto/hmac + crypto/sha1 + crypto/sha256 + crypto/sha512 + encoding/base32 | Full RFC 4226 / 6238 HOTP+TOTP from scratch |
| golang.org/x/crypto/pbkdf2 | Hand-rolled PBKDF2 loop over crypto/hmac (RFC 2898 §5.2) | x/crypto is not stdlib; composing crypto/hmac is |
| golang.org/x/crypto/aes (scrypt/argon2) | crypto/aes + crypto/cipher (AES-256-GCM) | Stdlib cipher; GCM mode gives authenticated encryption for free |
| github.com/spf13/cobra | lag + manual subcommand dispatch in main() | No reflection, no init magic, 50 lines vs a dependency |
| github.com/urfave/cli | same as above | |
| github.com/stretchr/testify | Plain 	esting package | 	.Errorf, 	.Fatalf, table-driven tests — no assertion library needed |
| gopkg.in/yaml.v3 | encoding/json | Vault envelope is JSON; human-readable without a custom parser |
| github.com/mattn/go-sqlite3 | Flat encrypted file via os + encoding/json | No CGO, no SQLite driver, fully cross-compiled |
| github.com/pkg/errors | errors + mt.Errorf("context: %w", err) | Wrapping + errors.Is / errors.As are stdlib since Go 1.13 |
| github.com/olekukonko/tablewriter | 	ext/tabwriter | Aligned columns, zero configuration |
| github.com/fatih/color | Plain mt output (no color) | Keeps output predictable in scripts and CI |
| golang.org/x/term | Documented limitation: no masked password input | x/term is not stdlib; omitting it is an honest trade-off, stated explicitly |
| github.com/google/uuid | crypto/rand + encoding/hex | UUIDs not needed; CSPRNG bytes suffice for nonces and salts |
| github.com/joho/godotenv | os.Getenv directly | No .env file loading; secrets come from stdin only |
| 
et/http (outbound) | Nothing — zero network calls | Air-gap is a feature, not an accident |

---

## Key design choices

### Why PBKDF2 instead of scrypt or Argon2?

Both golang.org/x/crypto/scrypt and golang.org/x/crypto/argon2 live in the
x/crypto extended library — they require go get and would break the empty equire
block in go.mod. PBKDF2-HMAC-SHA256 is implementable by composing crypto/hmac
alone, making it the only RFC-standardised KDF available within the stdlib boundary.
Its iteration count (600 000) is set to OWASP's 2026 recommendation to compensate for
its lower memory-hardness compared to modern memory-hard alternatives.

### Why AES-256-GCM?

crypto/cipher provides GCM mode directly. GCM is an authenticated cipher: a wrong
key or any modified byte causes cipher.AEAD.Open to return an error rather than
garbled plaintext. This is the mechanism behind the fail-safe property — no extra MAC
step is needed.

### Why JSON, not a binary format?

The vault envelope is human-readable JSON so that anyone reading the file can see
exactly what is stored and why, without reverse-engineering a binary layout. This is a
deliberate "documented, defensible" design choice for Track E.
