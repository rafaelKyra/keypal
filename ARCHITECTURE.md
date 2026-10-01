# Vaultling — Architecture & Threat Model

**Design document — Phase 1 + Phase 2**


> **Status note (v1.0.0).** This is the original design document, written when the
> project was called VALU (later, briefly, Keypal). It describes intent as well as fact, and parts of it are
> out of date. Checked against the source at this commit:
>
> - **Implemented:** encrypted vault with per-field AEAD (AES-256-GCM and
>   ChaCha20-Poly1305), Argon2id + HKDF-SHA256, mlock-backed secret buffers, secure
>   erase, unlock circuit breaker, log redaction, TOTP (RFC 6238), CSV import and
>   export, **KeePass (KDBX) import**, a D-Bus service (`vaultling serve`), a CLI and an
>   egui desktop application.
> - **Not implemented**, although the text below mentions them: auto-type,
>   hardware-token hooks, a browser extension, sync, and writing KDBX files.
> - **"Future Phases" (section 8)** is partly done: KDBX import, the D-Bus service
>   and the GUI exist; the rest has not been started.
> - **Legacy identifiers kept on purpose:** the HKDF labels `valu/...`, the D-Bus
>   name `org.rafa.Valu1` and the `.local/share/valu` path. They are on-disk or
>   runtime identifiers; changing them would make existing vaults unreadable.

---

## 1. Design Philosophy

Vaultling set out to combine the feature set of KeePassXC (KDBX4 compatibility, hardware-token hooks, auto-type — goals, not implemented; see the status note above) with the radical privacy and ephemeral key-management concepts of rafa.ai:

- **Memory-safe core**: Rust end-to-end; no C++ FFI except `libc` for `mlockall`.
- **Zero plaintext at rest**: every secret column is AEAD-encrypted (AES-256-GCM or ChaCha20-Poly1305) before it touches SQLite.
- **Dual-mode key lifecycle**: Volatile (ephemeral, RAM-only) and Passphrase (Argon2id-derived).
- **Secure Erase Protocol**: re-encrypt → delete → WAL truncate → VACUUM → zeroize keys.
- **Circuit Breaker**: state machine for unlock attempts to prevent memory-level brute force.
- **Strict Log Redaction**: `Secret<T>` wrapper + fixed-token rendering; no passwords, TOTP secrets, or file paths in logs.

---

## 2. Threat Model (Phase 1)

### 2.1 Swap-to-Disk

**Threat**: The kernel may page secret buffers to swap, leaving plaintext on disk after process exit.

**Mitigation**:
- `mlockall(MCL_CURRENT | MCL_FUTURE)` at process start (`secure_mem::harden_process_memory`).
- `RLIMIT_CORE=0` — no core dumps can capture secrets.
- `MADV_DONTDUMP` on transient secret regions (KDBX XML parse, large AEAD buffers).
- If `mlockall` fails (no `CAP_IPC_LOCK`), the app logs a **loud warning** and continues in degraded mode — the user must know swap risk exists.

### 2.2 Residual Memory After Drop

**Threat**: Rust does not guarantee zeroization on drop; the compiler may elide or hoist wipe operations.

**Mitigation**:
- Every secret type implements `ZeroizeOnDrop` (via the `zeroize` crate).
- Buffers are written with an explicit volatile store loop (`SecureBuffer::new_zeroed`, `MasterKey::destroy`).
- `SecureBuffer` hands out `&[u8]` only within the owning scope — no `Clone`, no interior mutability.

### 2.3 Core Dumps / Crash Tooling

**Threat**: A crash mid-operation may dump secret buffers to `/var/crash`.

**Mitigation**:
- `RLIMIT_CORE=0` set at startup, before any secret is allocated.
- All secrets live in `mlock`ed anonymous memory that never maps to a file.
- `MADV_DONTDUMP` on large transient regions (KDBX XML parse, AEAD scratch).

### 2.4 Memory-Level Brute Force

**Threat**: An attacker with local read access can repeatedly call `unlock(passphrase)` and observe timing/success. Argon2id is slow per attempt, but an unbounded loop still lets them burn CPU/GPU indefinitely or probe for side-channels.

**Mitigation**: Circuit Breaker state machine (see §4).

### 2.5 Secret Leakage via Logs / Telemetry

**Threat**: Passwords, TOTP secrets, file paths, and master-key material must never appear in `tracing` output, stderr, journald, or any log sink. Even *lengths* of passwords can be a side-channel.

**Mitigation**:
- Every sensitive value is wrapped in `Secret<T>` before crossing a logging boundary.
- `Debug`/`Display` impls render only a fixed token (`•••`) — never the inner value, never its length.
- String fields (paths, hostnames) are redacted via `StringPolicy::PartialMask` or `FullRedact`.

---

## 3. Key Lifecycle (Phase 1)

### 3.1 Volatile Mode (Ephemeral)

```text
┌─────────────────────────────────────────────────────────────┐
│  create_volatile()                                          │
│  ─────────────────                                          │
│  1. Allocate SecureBuffer(32) — mlocked, zeroed            │
│  2. Fill with OsRng (CSPRNG)                                │
│  3. Derive subkeys via HKDF-SHA256:                         │
│       enc_key  = HKDF(master, "valu/enc/v1")                │
│       mac_key  = HKDF(master, "valu/mac/v1")                │
│       wipe_key = HKDF(master, "valu/wipe/v1")               │
│  4. Return KeySession { master, enc, mac, wipe }            │
└─────────────────────────────────────────────────────────────┘

On process exit / drop():
  • MasterKey::drop() → zeroize raw key (volatile store)
  • KeySession::drop() → zeroize enc/mac/wipe subkeys
  • SecureBuffer::drop() → ZeroizeOnDrop wipes backing Vec
  • mlocked pages are freed to the OS; no swap, no core dump
```

**Unrecoverable by design**: if the app restarts, there is no passphrase to re-derive. The user must create a new volatile vault (old ciphertext becomes cryptographically unrecoverable — this is the intended "rafa.ai" property).

### 3.2 Passphrase Mode

```text
┌─────────────────────────────────────────────────────────────┐
│  create_passphrase(pass, salt)                               │
│  ─────────────────────────                                  │
│  1. Argon2id (RFC 9106, memory-hard):                        │
│       time_cost = 3                                          │
│       memory_cost = 64 MiB                                   │
│       parallelism = 4                                        │
│     → 32-byte master key                                     │
│  2. Zeroize the passphrase copy (caller's responsibility)    │
│  3. Derive subkeys via HKDF-SHA256 (same as volatile)        │
└─────────────────────────────────────────────────────────────┘

On-disk artifacts:
  • salt (16 bytes, NOT secret — makes KDF outputs unique per vault)
  • Argon2id parameters (stored in meta table for future upgrades)
  • ciphertext + nonce + tag (AEAD output)
```

**Recoverable**: the user can re-derive the same key from the passphrase + salt at any time. The circuit breaker state is sealed under `mac_key` so lockouts survive restarts.

### 3.3 Key Separation (HKDF-SHA256)

The master key is **never used directly** for encryption. We derive domain-separated subkeys:

| Subkey | Domain Label | Purpose |
|--------|--------------|---------|
| `enc_key` | `"valu/enc/v1"` | AEAD data-encryption (AES-256-GCM / ChaCha20-Poly1305) |
| `mac_key` | `"valu/mac/v1"` | Integrity tag / circuit-breaker state sealing |
| `wipe_key` | `"valu/wipe/v1"` | Secure Erase Protocol key (Phase 2) |

This ensures a leak of one domain never compromises the others.

---

## 4. Circuit Breaker (Phase 1)

### 4.1 State Machine

```text
       ┌──────────┐  N failures   ┌─────────────┐  cooldown elapses  ┌──────────┐
       │  CLOSED  │ ───────────► │    OPEN     │ ─────────────────► │ HALF-    │
       │ (accept) │              │ (reject all)│                    │ OPEN     │
       └──────────┘              └─────────────┘                    └──────────┘
            ▲                                          │ reset (admin/timeout)
            └──────────────────────────────────────────┘
```

- **CLOSED**: normal operation; failures are counted.
- **OPEN**: after `threshold` consecutive failures, all unlock attempts are rejected for a backoff window that grows exponentially (`base * 2^trip_count`).
- **HALF_OPEN**: after the window elapses, exactly one probe attempt is allowed. Success → CLOSED (counter reset). Failure → OPEN with a longer window.

### 4.2 Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `threshold` | 5 | Consecutive failures before tripping OPEN |
| `base_backoff` | 30 s | Initial backoff window; doubles each trip |
| `max_backoff` | 1 h | Maximum backoff window — beyond this the vault demands a full reset |

### 4.3 Persistence

The breaker state is sealed under `mac_key` (XOR-fold with the MAC subkey) so it cannot be tampered with by writing to disk. An attacker can't just delete the lockout file — the seal won't verify, and the vault resets to a safe OPEN state.

---

## 5. Secure Erase Protocol (Phase 2)

### 5.1 Why "Delete" Is Not Enough on Linux

Standard `DELETE FROM entries` leaves the plaintext (or ciphertext) in:
1. **WAL file** (`*.db-wal`) — un-checkpointed pages persist until truncation.
2. **SQLite page cache / freelist** — freed pages are reused, not zeroed.
3. **OS page cache** — the kernel may hold dirty pages in RAM long after close.
4. **Core dumps / crash tooling** — if a dump fires mid-operation.

### 5.2 The Protocol (6 Steps)

```text
 1. DERIVE    wipe_key = HKDF(master, "valu/wipe/v1")     ← domain-separated, one-shot
 2. RE-ENCRYPT every row under wipe_key (overwrites old ciphertext in-place)
 3. DELETE    all rows from `entries` and `meta`
 4. CHECKPOINT + TRUNCATE WAL   → forces WAL pages to be written & file truncated to 0
 5. VACUUM    → rewrites the entire DB file; old pages (holding stale ciphertext)
               are freed back to the OS. Combined with mlock, they never hit swap.
 6. ZEROIZE   wipe_key + all in-memory key material; close connection
```

After step 5 the on-disk file contains **only** the schema (no data pages), and every prior ciphertext has been overwritten by a different key's output — so a page *written by the erase* is undecryptable without the now-destroyed wipe_key. **Limit:** the erase cannot reach copies it did not write. A page from *before* step 2 that survives elsewhere — in remapped SSD blocks (wear levelling), a journal, a copy-on-write snapshot or a backup — still holds ciphertext under the original key, which is derived from the passphrase and is not destroyed. Whoever holds such a copy and the passphrase can still read it.

### 5.3 Safety Contract

- Must be called while the vault is **unlocked** (we need the master key to derive wipe_key).
- After this returns, the database contains zero user data and the wipe key is destroyed.
- The caller should then `close()` the `KeySession` to destroy the master key too.

---

## 6. Storage Architecture (Phase 2)

```text
┌─────────────────────────────────────────────────────────────┐
│                    VaultDatabase (public API)               │
├─────────────────────────────────────────────────────────────┤
│  SqlCipherLayer                                             │
│   • per-row AEAD (AES-256-GCM / ChaCha20-Poly1305)          │
│   • nonce = f(domain, row_id) → uniqueness under fixed key  │
│   • circuit-breaker state sealed under mac_key              │
├─────────────────────────────────────────────────────────────┤
│  SQLite (rusqlite, bundled)                                 │
│   • PRAGMA journal_mode=WAL                                  │
│   • PRAGMA synchronous=NORMAL                                │
│   • PRAGMA temp_store=MEMORY  ← no plaintext in /tmp        │
├─────────────────────────────────────────────────────────────┤
│  SecureEraseProtocol (secure_erase.rs)                      │
│   1. derive wipe_key from master key                        │
│   2. re-encrypt every row under wipe_key (overwrites ct)    │
│   3. DELETE rows                                            │
│   4. TRUNCATE WAL + checkpoint                               │
│   5. VACUUM (rewrites file; old pages freed to OS)          │
│   6. zeroize in-memory key material                          │
└─────────────────────────────────────────────────────────────┘
```

### 6.1 Schema

Every secret column is `BLOB` (ciphertext) + nonce + tag:

```sql
CREATE TABLE IF NOT EXISTS entries (
    id          INTEGER PRIMARY KEY,
    name_enc    BLOB NOT NULL,   -- AEAD(name)
    user_enc    BLOB NOT NULL,   -- AEAD(username)
    pass_enc    BLOB NOT NULL,   -- AEAD(password)  ← the crown jewel
    uri_enc     BLOB,            -- AEAD(uri), optional
    totp_secret BLOB,            -- AEAD(base32 TOTP secret)
    nonce       BLOB NOT NULL,   // 12-byte AEAD nonce (domain||id)
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB
);
```

### 6.2 Nonce Management

We use a 96-bit nonce built from a per-record counter: `nonce = domain(2 bytes) || record_id(8 bytes) || reserved(2 bytes)`. Uniqueness is guaranteed as long as `(key, domain)` pairs never repeat a counter. The `domain` byte distinguishes entries (1), meta (2), and wiped rows (0xFF).

---

## 7. Module Map

```text
valu/
  Cargo.toml                 ← dependencies + build config
  ARCHITECTURE.md            ← this file
  src/
    main.rs                  ← CLI entrypoint / lifecycle orchestration
    lib.rs                   ← public crate root, module wiring
    secure_mem.rs            ← Phase 1: zeroization, mlockall, SecureBuffer
    key_lifecycle.rs         ← Phase 1: Volatile vs Passphrase master keys
    circuit_breaker.rs       ← Phase 1: unlock-attempt state machine
    redaction.rs             ← Phase 1: log redaction wrapper
    storage/
      mod.rs                 ← Phase 2: encrypted DB wrapper (SqlCipher)
      secure_erase.rs        ← Phase 2: wipe key, WAL truncate, VACUUM
    crypto/
      mod.rs                 ← AEAD helpers (AES-256-GCM / ChaCha20-Poly1305)
      kdf.rs                 ← Argon2id parameter policy + HKDF domain separation
  tests/                     ← integration tests (zeroization, erase)
```

---

## 8. Future Phases

### Phase 3: KDBX4 Integration & Data Models
- Use the `keepass` crate for KDBX4 XML parsing/serialization.
- Custom cryptography, memory-wrapping, and key-lifecycle layers around it.
- TOTP & 2FA: native TOTP generation with secure memory isolation.

### Phase 4: Linux D-Bus & Secret Service Integrations
- FreeDesktop.org Secret Service API (D-Bus) to replace Gnome Keyring.
- SSH Agent integration (forwarding unlocked keys).
- Auto-Type (Secure input injection for Wayland/X11).
- Browser integration bridge (Native Messaging).

### Phase 5: UI/UX & Circuit Breaker Status
- Tauri/React or Python/PyQt6 frontend.
- Real-time circuit breaker status display.
- Hardware token hooks (YubiKey/OnlyKey challenge-response).

---

## 9. Security Guarantees

| Guarantee | Mechanism |
|-----------|-----------|
| No plaintext at rest | AEAD encryption of every secret column before SQLite insert |
| No swap-to-disk | `mlockall(MCL_CURRENT \| MCL_FUTURE)` + `RLIMIT_CORE=0` |
| Zeroization on drop | `ZeroizeOnDrop` + explicit volatile-store wipe loops |
| Unrecoverable volatile keys | CSPRNG in RAM; no passphrase to re-derive after exit |
| Brute-force resistance | Argon2id (64 MiB, 3 iterations) + Circuit Breaker state machine |
| Secure erase | Re-encrypt → delete → WAL truncate → VACUUM → zeroize keys |
| Log redaction | `Secret<T>` wrapper + fixed-token rendering; no lengths leaked |

---

## 10. References

- [Argon2id (RFC 9106)](https://datatracker.ietf.org/doc/html/rfc9106)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [KDBX4 Format Specification](https://keepass.info/kdbx_xml_format.html)
- [FreeDesktop Secret Service API](https://specifications.freedesktop.org/secret-service/latest/)
