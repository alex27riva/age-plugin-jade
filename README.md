# age-plugin-jade

An [age](https://age-encryption.org) plugin that uses a **Blockstream Jade** hardware wallet as the decryption key.

```
age -r age1jade1q2shxdc... -o secret.age secret.txt      # offline, no device needed
age -d -i jade-identity.txt secret.age > secret.txt       # Jade asks you to confirm
```

> **Status: experimental.** Tested end-to-end with age v1.3.2 against a protocol-accurate mock device. It has **not yet been run on real Jade hardware** and has not been audited. Keep a backup recipient (see below) until you trust it.

## How it works

Jade firmware implements SLIP-0013/0017 identity keys, intended for SSH and GPG. `age-plugin-jade` uses the SLIP-0017 ECDH key:

- **Key derivation.** The key is derived on the device from your wallet seed, an identity URI (default `ssh://age@jade`) and an index. The curve is NIST P-256, the only one Jade supports for identities. The private key never leaves the Jade.
- **Encryption** needs only the public key, so it runs anywhere and never touches the device. Each file gets an ephemeral P-256 key; the file key is wrapped with HKDF-SHA-256 and ChaCha20-Poly1305 (same construction as `age-plugin-yubikey`'s `piv-p256`).
- **Decryption** sends the file's ephemeral public key to the Jade (`get_identity_shared_key`). Jade shows the identity URI and **waits for you to confirm on screen**, then returns the ECDH shared secret, which unwraps that file's key.

Before prompting, the plugin checks that the connected Jade derives the expected public key. With the wrong device, seed or BIP-39 passphrase you get a clear error, not a pointless confirmation.

## Install

```sh
make tidy          # first time only: resolves deps and writes go.sum
make install       # builds and installs to ~/.local/bin/age-plugin-jade
```

age finds plugins by name on `$PATH`. You also need `age` itself (`sudo dnf install age` on Fedora).

**Linux serial permissions:** Jade appears as `/dev/ttyACM0` or `/dev/ttyUSB0`. Add yourself to `dialout` (`sudo usermod -aG dialout $USER`, then log out and in).

## Usage

1. Plug in the Jade and get it to the main screen. You will enter your PIN on the device when asked.
2. Generate an identity file. This reads a public key only; no confirmation is needed.
   ```sh
   age-plugin-jade --generate -o ~/.config/age/jade.txt
   # Public key: age1jade1...
   ```
3. Encrypt and decrypt:
   ```sh
   age -r age1jade1... -o notes.age notes.txt
   age -d -i ~/.config/age/jade.txt notes.age
   ```

Other commands:

```sh
age-plugin-jade -y jade.txt                    # identity file → recipient (offline)
age-plugin-jade --generate --index 1           # a second, independent key
age-plugin-jade --generate --uri 'gpg://Me <me@example.com>'
age -e -i jade.txt -o x.age x.txt              # identity file works as a recipient too
```

| Setting | Flag | Env (also used when age runs the plugin) | Default |
|---|---|---|---|
| Serial port, or `tcp:HOST:PORT` | `--port` | `JADE_PORT` | auto-detect by USB VID/PID |
| Network the wallet is locked to | `--network` | `JADE_NETWORK` | `mainnet` (use `testnet` for test wallets) |

## Security model — read this

- **The identity file contains no secret.** It holds only the URI, index and public key. If you lose it, regenerate it with the same URI and index.
- **Your seed is the key.** Anyone with your mnemonic (and passphrase) can derive this key and decrypt your files. Your seed backup is also your file backup. A different BIP-39 passphrase gives a different key.
- **One confirmation per file.** Jade's screen shows the identity URI, not the file name. Malware on your computer could swap in another file encrypted to you and get it decrypted with your confirmation. It can never extract the private key. This is the same model as a YubiKey with touch.
- **Unlocking uses the blind PIN server.** A locked Jade unlocks through Blockstream's PIN server, or your own if configured. The plugin relays that exchange, so unlocking needs network access. An already-unlocked Jade needs none.
- **Header linkability.** Each stanza carries a 4-byte tag of the recipient public key (as `age-plugin-yubikey` does), so files encrypted to the same key can be linked.
- **Add a backup recipient.** If the Jade dies, restoring the seed on a new Jade recovers everything. As an extra safety net, also encrypt to an offline X25519 key:
  ```sh
  age-keygen -o backup.txt           # store offline / on paper
  age -r age1jade1... -r age1<backup> -o file.age file
  ```

### Device requirements

- Firmware with SSH/GPG identity support: any reasonably recent version. An "unknown method" error means you should update.
- A wallet whose seed is stored on the device. Wallets loaded in some older ways only keep the derived master key. Jade then reports *"Feature requires resetting Jade"*; wiping and restoring from the mnemonic fixes it.

## Testing without hardware

`cmd/jade-mock` is a software Jade that speaks the same CBOR-RPC protocol over TCP. It mirrors the firmware's SLIP-0010/0017 derivation and includes a fake PIN server, so the unlock relay is exercised. It is **insecure**; never give it a real mnemonic.

```sh
make test          # unit + mock-device integration tests
make e2e           # real age CLI + plugin + mock devices (needs age on PATH)

./bin/jade-mock &  # interactive: listens on 127.0.0.1:30121
JADE_PORT=tcp:127.0.0.1:30121 age-plugin-jade --generate
```

Blockstream's official QEMU emulator (`Dockerfile.qemu` in the Jade repo) also listens on TCP port 30121, so `JADE_PORT=tcp:localhost:30121` works with it as well.

### First test on a real Jade (suggested)

1. Use a **test wallet**: restore a throwaway mnemonic, or use Jade's temporary/emergency restore.
2. Run `age-plugin-jade --generate`, then generate again and check the key is identical.
3. Encrypt a test file, decrypt it, and confirm on the device.
4. Decline on the device once and check that you get `decryption declined on the Jade`.
5. Unplug, replug and decrypt again.

## Wire format (v1)

```
Recipient:  age1jade1...         bech32(compressed P-256 pubkey, 33 bytes)
Identity:   AGE-PLUGIN-JADE-1... bech32(0x01 || index u32be || pubkey (33) || URI)

Stanza:     -> jade-p256 <tag> <epk>
            <body>

tag     = b64(SHA-256(pubkey)[:4])
epk     = b64(compressed ephemeral pubkey)
shared  = ECDH(eph, pubkey).X                       (on decrypt: computed by Jade)
wrapKey = HKDF-SHA-256(ikm=shared, salt=epk||pubkey, info="age-plugin-jade/v1/jade-p256")
body    = ChaCha20-Poly1305(wrapKey, nonce=0^12, fileKey)   (32 bytes)
```

Jade derives the key as SLIP-0010 nist256p1 from the seed. The path is `m/17'/h0'/h1'/h2'/h3'`, where `hN` are the little-endian 32-bit words of `SHA-256(LE32(index) || URI)` (see `main/identity.c` in the Jade firmware).

## Layout

```
main.go              CLI and plugin wiring (filippo.io/age/plugin)
age.go               Recipient/Identity: stanza wrap/unwrap
keys.go              encodings, URI validation, point (de)compression
session.go           connect, unlock, verify key, prompt
jade/                minimal Jade CBOR-RPC client (serial/TCP, auth_user + PIN server relay)
internal/mockjade/   software Jade for tests
cmd/jade-mock/       mock as a standalone TCP server
```
