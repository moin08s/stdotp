# 5-Minute Hackathon Video Demo Recording Script

**Project:** `stdotp` (Zero-Dependency CLI TOTP/HOTP Authenticator & Encrypted Vault)  
**Track:** Track E (Security & Crypto Utilities) · Go 1.27  
**Target Video Duration:** 4 to 5 Minutes  

---

## 🎬 Video Recording Plan & Step-by-Step Walkthrough

### 0:00 – 0:45 | Introduction & Zero-Dependency Proof
- **Speaker:** *"Hi everyone! This is `stdotp` — a zero-dependency CLI 2FA authenticator with an AES-256-GCM encrypted vault built for Track E of the Zero Dependency Hackathon 2026."*
- **Terminal Action 1:** Show zero external dependencies:
  ```sh
  go list -m all
  ```
  *(Point out: Only `stdotp` is printed — 0 external packages, empty `require` block in `go.mod` on Go 1.27).*
- **Terminal Action 2:** Show air-gapped compilation:
  ```sh
  GOPROXY=off go build -o stdotp .
  ```
  *(Point out: Compiles cleanly with zero network calls).*

---

### 0:45 – 1:30 | Single-Binary Cryptographic Self-Test (Single File Bonus)
- **Speaker:** *"Before touching any vault, let's verify our cryptographic primitives in-process."*
- **Terminal Action:** Run self-test:
  ```sh
  ./stdotp self-test
  ```
  *(Point out: In-process validation of RFC 4226 HOTP, RFC 6238 TOTP across SHA1/256/512, RFC 7914 §11 PBKDF2 vectors, AES-256-GCM round-trip, and native Go 1.27 stdlib `uuid` generation).*

---

### 1:30 – 2:30 | Interactive Vault Initialization & Account Setup
- **Speaker:** *"Let's initialize our encrypted vault with OWASP 2026 recommended 600,000 PBKDF2 iterations."*
- **Terminal Action 1:** Initialize vault:
  ```sh
  ./stdotp init --iterations=600000
  ```
  *(Enter master password twice).*
- **Terminal Action 2:** Add an account securely:
  ```sh
  ./stdotp add github
  ```
  *(Enter master password, then paste `JBSWY3DPEHPK3PXP`).*
- **Terminal Action 3:** List accounts in table and JSON formats:
  ```sh
  ./stdotp list
  ./stdotp list --json
  ```
  *(Point out: Aligned columnar formatting via stdlib `text/tabwriter`, machine-parseable JSON array).*

---

### 2:30 – 3:30 | Token Generation, Two-Way 2FA Verification & Stdio Discipline
- **Speaker:** *"Now let's generate a 6-digit TOTP token and test our two-way verification engine."*
- **Terminal Action 1:** Generate code:
  ```sh
  ./stdotp code github
  ```
  *(Point out: Real-time countdown timer `(18s remaining)`).*
- **Terminal Action 2:** Verify the token (Server-Side 2FA verification):
  ```sh
  ./stdotp verify github <generated_code>
  ```
  *(Point out: `Valid code (drift: 0 steps)` with constant-time comparison).*
- **Terminal Action 3:** Show UNIX pipeable stream separation:
  ```sh
  ./stdotp code github | clip
  ```
  *(Point out: Password prompt went to `stderr`, only the clean 6-digit token went to clipboard via `stdout`).*

---

### 3:30 – 4:15 | Vault Security: Rekeying & Diagnostics
- **Speaker:** *"Let's check our authenticator diagnostics and rotate our master password."*
- **Terminal Action 1:** System & Vault Health Check:
  ```sh
  ./stdotp status
  ```
  *(Point out: Vault size, last modification time, KDF iterations, UTC step alignment).*
- **Terminal Action 2:** Atomic Vault Rekeying:
  ```sh
  ./stdotp change-password
  ```
  *(Rotate to new password; explain atomic write via `.stdotp-UUID-*.tmp` -> `fsync` -> `os.Rename`).*

---

### 4:15 – 5:00 | Automated Tests & Reproducible Build Proof
- **Speaker:** *"Finally, let's run our test suite and prove reproducible bit-for-bit compilation."*
- **Terminal Action 1:** Run full test suite:
  ```sh
  go test -v -cover .
  ```
  *(Point out: **56 test suites passing (100% pass)** with 81.1% statement coverage covering RFC vectors, AES-256-GCM AAD binding, Windows UTF-8 BOM stripping, timestamp modulo normalisation, and concurrency lockfile protection).*
- **Terminal Action 2:** Reproducible build hash:
  ```sh
  CGO_ENABLED=0 go build -trimpath -ldflags="-buildid=" -o stdotp .
  Get-FileHash -Algorithm SHA256 stdotp.exe
  ```
  *(Point out: Bit-for-bit identical SHA-256 hash `F89D7608F3C43338940E61A861910EC83AA1AFB7434F782A5B27F60853CD1E9D` across any clean build directory).*
- **Closing:** *"Thank you! `stdotp` replaces `github.com/pquerna/otp` and `github.com/google/uuid` with 100% standard library code."*
