# Vaultling

An offline vault for passwords, keys, cards and notes. Written in Rust, for Linux.
Everything stays on your machine: there is no account, no sync and no network
component in the vault itself.

**Status:** v1.0.0 · 119 unit tests · Linux only · **not independently audited**.
Treat it accordingly: read the code and the limits below before you trust it with
anything you cannot afford to lose.

## What it does

- **Encrypted local vault.** Entries live in SQLite, and every secret field (name,
  username, password, URI, TOTP secret) is encrypted separately with an AEAD cipher
  before it reaches the database. Both AES-256-GCM and ChaCha20-Poly1305 are
  implemented.
- **Sixteen kinds of entry,** each with its own form: website, email, authenticator,
  API key, SSH key, server, database, Wi-Fi, device, VPN, certificate, recovery codes,
  crypto wallet, bank card, secure note and software licence.
- **TOTP codes** (RFC 6238).
- **Import and export.** CSV import and export, and KeePass (KDBX) import. The CSV
  export is plaintext by necessity — it is the only format every other tool reads —
  and is written with owner-only permissions.
- **Trash with restore, and entry history.** Deleted entries can be restored or
  purged; purging overwrites every secret column with random data (encrypted under a wipe key) instead of a plain `DELETE`.
- **Interfaces.** A desktop application (`vaultling-gui`, egui), a command-line tool
  (`vaultling`) and an optional D-Bus service (`vaultling serve`).

## How it protects secrets

| Concern | What the code does |
|---|---|
| Master key | Argon2id, then HKDF-SHA256 to separate encryption, authentication and wipe keys |
| At rest | Per-field AEAD with its own nonce; history rows get their own nonces too |
| In memory | Secret buffers lock their own pages with `mlock` and are zeroized on drop; core dumps disabled (`RLIMIT_CORE=0`); transient buffers marked `MADV_DONTDUMP` |
| Guessing | A circuit breaker on unlock attempts |
| Deleting | A secure-erase protocol: re-encrypt, delete, truncate the WAL, `VACUUM`, zeroize keys |
| Logs | A redaction wrapper; passwords, TOTP secrets and file paths are not logged |
| Screen and clipboard | The GUI locks after 5 minutes idle and when minimised; a copied secret is overwritten in the clipboard after 20 seconds |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the threat model. It was written as a
design document, so it also lists goals that were not built — its status note says
which.

## What it does not do

- No auto-type, no hardware-token (YubiKey/FIDO) support, no browser extension.
- No sync or cloud backup. Your vault is a file; back it up yourself.
- No KDBX export — KeePass databases can be imported, not written.
- No Windows or macOS build is provided yet.
- Not audited by anyone but its author.

**Memory locking under default limits.** Argon2id asks for a 64 MiB working buffer,
which cannot be locked when `RLIMIT_MEMLOCK` is at the common default of 8 MiB. Vaultling
then warns and continues: key material is still locked per buffer, and the remaining
exposure is Argon2's temporary working memory during key derivation. Raise the limit
(`ulimit -l`) or grant `CAP_IPC_LOCK` to close that gap.

## Intended use and limits

- **Use it for your own data.** Vaultling is a password and secrets vault. It is not designed to
  obstruct a lawful investigation or to destroy data you are legally obliged to keep. You are
  responsible for complying with the law where you live, including any rules on encryption
  software.
- **Secure erase has limits.** It overwrites what it can reach, but it cannot reach copies it
  did not write: remapped SSD blocks, journals, copy-on-write snapshots and backups can still
  hold older ciphertext, readable by anyone who also has your passphrase. Do not rely on it
  as a guarantee that data cannot be recovered.
- **No warranty.** The Apache License disclaims warranty and liability. The code is not
  independently audited. Keep your own backups of the vault file.
- **Name.** Vaultling was called VALU and, briefly, Keypal. Other products use similar
  names; this project is unrelated to them.

## Build and test

```bash
cargo build --release        # produces target/release/vaultling and vaultling-gui
cargo test                   # 119 unit tests
```

The desktop application needs the usual X11 or Wayland client libraries.

CLI usage, for scripting and testing (passphrases on the command line are visible to
other local users; use the GUI for real data):

```bash
vaultling create <vault> <passphrase>
vaultling add    <vault> <passphrase> <name> <username> <password>
vaultling get    <vault> <passphrase> <name>
```

## Compatibility note for maintainers

The project was called VALU until 1.0.0, then Keypal, and is now Vaultling. A few identifiers keep the old name **on
purpose**: the HKDF domain-separation labels (`valu/enc/v1`, `valu/mac/v1`,
`valu/wipe/v1`, `valu/keyfile/v1`, `valu/breaker/v1`), the D-Bus name `org.rafa.Valu1`
and the `.local/share/valu` path. The labels are inputs to key derivation: changing
one makes every existing vault unreadable. Do not rename them as a cleanup. The portable-mode marker `.keypal-portable` of earlier installs is
still honoured alongside `.vaultling-portable`.

## Developing the interface without a screenshot tool

Wayland refuses X11 screen capture, so the GUI can photograph itself. Setting
`VAULTLING_SHOT=/path/out.png` writes a PNG of the window and exits; F12 captures on demand.
Further `VAULTLING_SHOT_*` variables (vault, panel, theme, search, scroll) drive it to a
given screen. See `examples/seed_demo.rs` for a demo vault filled with fake data.

This is a development affordance. It is off unless the variable is set, but it exists
in release builds, and with `VAULTLING_SHOT_VAULT` and `VAULTLING_SHOT_PASS` it will open a
vault and write an image of its unlocked contents. Never set these outside development.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The Apache license
covers the code. The name "Vaultling" and the mascot image are not licensed for reuse; see
`NOTICE`. The bundled monospace font keeps its own license in `assets/LICENSE-DejaVu.txt`.

Copyright 2026 Rafael Kyra.
