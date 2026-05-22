# dirtydecrypt-go

> One byte. One in 256. No race.

Go port of [dirtydecrypt](https://github.com/v12-security/pocs/tree/main/dirtydecrypt) (CVE-2026-46400). Member of the [Dirty Frag](https://github.com/V4bel/dirtyfrag) vulnerability class.

## How it works (tl;dr)

The bug is in `rxgk_decrypt_skb()` (`net/rxrpc/rxgk_common.h`). The function is missing a call to `skb_cow_data()` before invoking the krb5enc AEAD. The AEAD decrypts the skb payload in-place - directly into whatever page backs the skb data. If that page is a page-cache page (pinned there via vmsplice + splice), the decryption overwrites the file's page cache.

**Why probabilistic**

Unlike fragnesia (AES-GCM keystream table), rxgk uses AES-128-CTS under a session key negotiated at call setup. We generate a fresh random 16-byte key per fire. The first byte of the AES-CBC decrypted block written back to `page_cache[i]` is uniformly random: 1/256 chance it equals the target byte.

**Sliding-window technique**

Each fire at offset `i` corrupts 16 bytes: `page_cache[i..i+15]`. Once `page_cache[i]` matches the target, we move to offset `i+1`. The next fire overwrites `page_cache[i+1..i+16]` - repairing the collateral damage from offset `i` without touching the already-written byte `i`. Forward-only, no revisits.

Expected fires per byte: ~256. Worst case: 10000 per byte.

**Trigger chain**

1. `add_key("rxrpc", ...)` - install a random AES-128 rxgk session key
2. `AF_RXRPC` client socket connects to a fake UDP server on loopback
3. Fake server sends a CHALLENGE (SecuIdx=6, rxgk)
4. Client responds; fake server builds a malicious DATA packet via `vmsplice` (wire header) + `splice` (file page at offset `i`)
5. `rxgk_decrypt_skb()` runs on the client - decrypts in-place, byte `i` of `/usr/bin/su` becomes random
6. mmap check: if `page_cache[i] == target[i]`, advance to `i+1`

192 bytes total. ~49152 fires on average. One SA. No race.

## Usage

```bash
go build -o dirtydecrypt-go .
./dirtydecrypt-go
```

On success drops into a root shell via PTY. The on-disk binary is untouched.

### Cleanup

```bash
echo 1 | tee /proc/sys/vm/drop_caches
```

## Requirements

- Linux - unpatched kernel (see below)
- No external tools - pure Go, single static binary
- Kernel module: `rxrpc` (autoloaded on `socket(AF_RXRPC, ...)`)

## Affected kernels

All kernels before the patch: https://lore.kernel.org/netdev/

Same range as the dirtyfrag family.

## Mitigation

```bash
rmmod rxrpc
printf 'install rxrpc /bin/false\n' > /etc/modprobe.d/dirtydecrypt.conf
```

## Compared to the family

| | dirtyfrag-go | fragnesia-go | **dirtydecrypt-go** |
|---|---|---|---|
| CVEs | CVE-2026-43284 / CVE-2026-43500 | CVE-2026-46300 | CVE-2026-46400 |
| Transport | ESP-in-UDP + RxRPC/rxkad | ESP-in-TCP (ULP) | RxRPC/rxgk |
| Write model | deterministic | deterministic (keystream table) | probabilistic (1/256) |
| Fires per byte | 1 (ESP) / 3 fixed writes (rxkad) | 1 (keystream lookup) | ~256 average |
| Crypto | CBC-AES / HMAC-SHA256 / fcrypt | AES-128-GCM | AES-128-CTS (krb5enc) |

## References

- [v12-security/pocs - dirtydecrypt](https://github.com/v12-security/pocs/tree/main/dirtydecrypt) - original C PoC
- [CVE-2026-46400](https://nvd.nist.gov/vuln/detail/CVE-2026-46400)

## Credits

- **Aaron Esau / V12 team** - vulnerability discovery and original PoC
