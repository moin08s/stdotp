# `stdotp` — Complete Demo Video Production Guide & Director's Script

**Project:** `stdotp` (Zero-Dependency CLI TOTP/HOTP Authenticator & Encrypted Vault)  
**Hackathon Track:** Track E (Security & Crypto Utilities) · Go 1.27  
**Target Video Length:** 4:30 – 4:55 Minutes (Hard limit: 5 minutes)  

---

## 🛠️ Recording Setup & Recommendations

### 1. Visual & Audio Environment
- **Screen Resolution:** 1080p (1920x1080) at 60 FPS.
- **Terminal Setup:**
  - Font: **JetBrains Mono**, **Cascadia Code**, or **Fira Code** at **18pt+** (ensures text is crisp and readable on mobile).
  - Terminal Window: Maximized or centered with generous margins.
  - Theme: High-contrast Dark theme (e.g., One Dark Pro, Dracula, or VS Code Dark+).
- **Software:** OBS Studio, Loom, or macOS QuickTime Screen Recording.
- **Audio:** Crisp microphone input without background echo or keyboard clatter.

---

## 🎬 Second-by-Second Director's Script

### 📍 Phase 1: The Hook & Zero-Dependency Proof (0:00 – 0:45)
*Goal: Immediately establish Track E compliance and prove zero dependencies before doing anything else.*

- **Visual:** Clean terminal showing project directory with `go.mod` visible.
- **Spoken Voiceover:**
  > *"Hello judges! This is `stdotp` — a standalone, zero-dependency 2FA authenticator and encrypted secrets vault built for Track E of the Zero Dependency Hackathon 2026."*
  > *"Let's prove our zero-dependency mandate right now."*
- **Terminal Commands:**
  ```sh
  # 1. Show zero dependencies
  go list -m all

  # 2. Show go.mod
  cat go.mod

  # 3. Prove offline air-gapped compilation
  GOPROXY=off go build -o stdotp .
  ```
- **Spoken Voiceover:**
  > *"As you can see, `go list -m all` prints only `stdotp`, `go.mod` has zero require statements, and `GOPROXY=off` builds cleanly offline. No supply-chain attack surface."*

---

### 📍 Phase 2: In-Process Cryptographic Self-Test (0:45 – 1:30)
*Goal: Highlight the Single File bonus (+5) and verify all RFC vectors on-screen.*

- **Visual:** Running the built-in self-test command.
- **Spoken Voiceover:**
  > *"To satisfy the Single File bonus, `stdotp` includes a built-in cryptographic self-test that verifies RFC compliance in-process without external test runners."*
- **Terminal Commands:**
  ```sh
  ./stdotp self-test
  ```
- **Spoken Voiceover:**
  > *"In a fraction of a second, it executes official RFC 4226 HOTP vectors, RFC 6238 TOTP across SHA1, SHA256, and SHA512, RFC 7914 §11 PBKDF2 vectors, AES-256-GCM authenticated encryption, and native Go 1.27 standard library UUID generation."*

---

### 📍 Phase 3: Vault Initialization & Account Ingestion (1:30 – 2:30)
*Goal: Demonstrate defensible key derivation and clean CLI ergonomics.*

- **Visual:** Initializing vault and adding accounts.
- **Spoken Voiceover:**
  > *"Now let's initialize our encrypted vault. By default, `stdotp` uses 600,000 PBKDF2-HMAC-SHA256 iterations per OWASP 2026 recommendations for GPU resistance."*
- **Terminal Commands:**
  ```sh
  # Initialize vault with 600k iterations
  ./stdotp init --iterations=600000

  # Add GitHub 2FA account interactively
  ./stdotp add github
  # (Enter master password, then paste secret: JBSWY3DPEHPK3PXP)

  # List vault accounts in tabular format and JSON
  ./stdotp list
  ./stdotp list --json
  ```
- **Spoken Voiceover:**
  > *"Accounts are stored under `~/.stdotp/vault.json` sealed with AES-256-GCM. We support human-readable tabular output via standard `text/tabwriter` and JSON arrays for machine scripting."*

---

### 📍 Phase 4: Token Generation & Two-Way 2FA Verification (2:30 – 3:30)
*Goal: Show OTP countdown, UNIX pipe discipline, and server-side verification.*

- **Visual:** Generating and verifying tokens.
- **Spoken Voiceover:**
  > *"Let's generate our current 6-digit TOTP token."*
- **Terminal Commands:**
  ```sh
  ./stdotp code github
  ```
- **Spoken Voiceover:**
  > *"Notice the real-time step countdown. Crucially, `stdotp` is not just a generator — it also provides server-side verification with clock-drift window tolerance."*
- **Terminal Commands:**
  ```sh
  # Verify token
  ./stdotp verify github <enter_the_generated_code>

  # Demonstrate UNIX pipe discipline
  ./stdotp code github | clip   # or pbcopy / xclip
  ```
- **Spoken Voiceover:**
  > *"Verification uses `crypto/subtle.ConstantTimeCompare` to eliminate timing side-channels. Furthermore, notice how UNIX piping sends only the raw 6-digit code to standard output while password prompts stay on standard error."*

---

### 📍 Phase 5: Vault Management, Rekeying & Diagnostics (3:30 – 4:15)
*Goal: Showcase crash-resilience, password rotation, and diagnostics.*

- **Visual:** Running doctor mode and rotating master password.
- **Spoken Voiceover:**
  > *"Let's inspect our authenticator health and rotate the master password."*
- **Terminal Commands:**
  ```sh
  # System & Vault Diagnostics
  ./stdotp status

  # Atomically re-encrypt vault with new password
  ./stdotp change-password
  ```
- **Spoken Voiceover:**
  > *"Our atomic file pipeline writes to a UUID temporary file, flushes hardware caches with `fsync`, sets `chmod 0600`, renames atomically, and syncs the parent directory. A power loss during write never leaves a corrupted vault."*

---

### 📍 Phase 6: Automated Tests & Reproducible Build Proof (4:15 – 4:55)
*Goal: Close with massive test coverage (56 test suites · 81.1% coverage) and bit-for-bit hash match.*

- **Visual:** Running test suite and verifying reproducible build hashes.
- **Spoken Voiceover:**
  > *"Finally, let's look at our automated test suite and prove reproducible bit-for-bit builds."*
- **Terminal Commands:**
  ```sh
  # Run 56 automated test suites with coverage
  go test -v -cover .

  # Show bit-for-bit reproducible build hash
  CGO_ENABLED=0 go build -trimpath -ldflags="-buildid=" -o stdotp .
  Get-FileHash -Algorithm SHA256 stdotp.exe
  ```
- **Spoken Voiceover:**
  > *"All 56 test suites pass with 81.1% statement coverage. In conclusion, `stdotp` proves you can eliminate `github.com/pquerna/otp` and `github.com/google/uuid` completely using pure Go standard library craft. Thank you!"*

---

## 🏆 Submission Text & Description (Copy-Paste Ready)

### Project Title
**`stdotp` — Zero-Dependency CLI TOTP/HOTP Authenticator & AES-256-GCM Encrypted Vault**

### Track
**Track E: Security & Crypto Utilities**

### Short Description (1-2 sentences)
*A standalone, crash-resilient 2FA authenticator with an AES-256-GCM encrypted vault, two-way verification, and OWASP 2026 PBKDF2 key derivation, built using 100% Go 1.27 standard library code.*

### Targeted Bonuses (+16 Max Points)
- **Single File (+5):** Full monolithic implementation in `stdotp.go` with in-process `self-test`.
- **Reproducible Build (+5):** Bit-for-bit identical SHA-256 hash (`F89D7608F3C43338940E61A861910EC83AA1AFB7434F782A5B27F60853CD1E9D`).
- **Package Killer (+3):** Replaces `github.com/pquerna/otp` (15M+ downloads) and `github.com/google/uuid` (80M+ downloads).
- **STDLIB Log (+3):** 15 standard library substitutions documented with rationales in `STDLIB.md`.
- **Write-Up Side Quest ($300):** Deep-dive publication article prepared in `WRITEUP.md`.
