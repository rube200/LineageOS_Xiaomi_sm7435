# Xiaomi sm7435 kernel

Kernel source to build **LineageOS on Qualcomm sm7435** (parrot). Developed on
**garnet** (Redmi Note 13 Pro 5G).

**Why this repo exists:** ship a working Lineage kernel for sm7435 phones. Two
things are custom here; everything else is normal platform support (display,
audio, Wi‑Fi, …).

| Feature | What it is | Where |
|---------|------------|-------|
| **KernelSU-Next** | Kernel-side root, pulled in as a git submodule rather than vendored | `KernelSU-Next/`, `drivers/kernelsu` |
| **WireGuard obfuscation** | VPN UDP packets are harder to detect and block than stock WireGuard, while crypto and the Noise protocol stay the same | `drivers/net/wireguard/` |

## KernelSU-Next (root)

Root support from [KernelSU-Next](https://github.com/KernelSU-Next/KernelSU-Next),
kept as a submodule so it stays out of this kernel's history. The whole
integration:

| Where | What |
|-------|------|
| `KernelSU-Next/` | Submodule pinned to a KernelSU-Next release; the weekly sync in `.github/workflows/sync-upstream.yml` moves it to the newest `vX.Y.Z` release tag |
| `drivers/kernelsu` | Symlink to `../KernelSU-Next/kernel` — only that subdir is built |
| `drivers/Kconfig` | `source "drivers/kernelsu/Kconfig"` |
| `drivers/Makefile` | `obj-$(CONFIG_KSU) += kernelsu/` |

Neither `git clone` nor `repo sync` fetches the submodule, and without it
`drivers/kernelsu` dangles and the build stops at `drivers/kernelsu/Kconfig`:

```
git submodule update --init --recursive
```

Run it again after every pull or `repo sync`. The recorded commit moves when
the weekly sync picks up a new release, and a checkout that lags behind still
builds, using the older KernelSU-Next. The build prints a warning from
`drivers/Makefile` when the checkout is not the recorded commit.

Keep the submodule a full clone (no `--depth`). KernelSU-Next takes its version
from its own git history at build time (30000 + number of commits) and prints
it as `-- KernelSU-Next version: …`. A shallow clone reports 30001, and a build
without `git` falls back to 1. The build warns about a shallow clone as well.

To move to another release by hand, check out its tag in the submodule and
commit the new pointer:

```
git -C KernelSU-Next fetch --tags origin
git -C KernelSU-Next checkout v3.4.2
git add KernelSU-Next
```

The weekly sync always sets the pointer to the newest release tag, so a manual
pin to anything else only lasts until the next sync.

`CONFIG_KSU` defaults to `y` and its dependencies (`KPROBES`, `EXT4_FS`) are
already set in `gki_defconfig`, so a normal build compiles root in with no
defconfig change here. For the remaining options and how root itself works, see
upstream.

## Weekly sync

`.github/workflows/sync-upstream.yml` runs every Thursday, and on manual
dispatch from the default branch. When LineageOS `lineage-23.2` has moved or
the submodule is not at the newest KernelSU-Next release tag (`vX.Y.Z`; side
lines such as `v3.4.0-legacy` are ignored), it:

1. rebases the commits of this repo onto the new upstream tip and folds the new
   KernelSU-Next pointer into the existing submodule commit;
2. pushes the result to the branch `sync-candidate`;
3. compiles `drivers/net/wireguard/` and `drivers/kernelsu/` from that branch
   (arm64, `gki_defconfig`, clang) in a job that only has a read-only token;
4. moves the default branch to the candidate and deletes `sync-candidate`, but
   only if the compile succeeded.

If the rebase conflicts or the compile fails, the default branch is left alone.
After a failed compile `sync-candidate` stays in place so the result can be
inspected; the next run overwrites it.

After each successful sync the tag `sync-upstream-base` is set to the upstream
commit the default branch now sits on. If LineageOS ever rewrites the history
of its branch, the next sync uses that tag to replay only this repo's commits,
and not the upstream commits that were dropped by the rewrite.

Every sync rewrites the default branch: it is force-pushed, and the rebased
commits get new hashes with `github-actions[bot]` as committer. To bring a
clone up to date afterwards:

```
git fetch origin
git reset --hard origin/lineage-23.2
git submodule update --init --recursive
```

Local commits and open pull requests have to be rebased onto the new branch.

`SYNC_TOKEN` is an optional repository secret: a personal access token with
write access to the repository contents. When it is set the workflow uses it
for checkout and push; otherwise it uses the built-in `GITHUB_TOKEN`. Set it
if the built-in token is not allowed to update the default branch.

---

## WireGuard obfuscation

The in-kernel WireGuard driver (`drivers/net/wireguard/`) can send its UDP
packets in two wire formats. Noise handshakes, session keys and
**ChaCha20-Poly1305** payload encryption are the same in both; only the bytes
on the network differ.

| Value | Format | What an observer sees |
|-------|--------|----------------------|
| 0 | standard | Plain WireGuard; works with stock WireGuard peers |
| 1 | obfuscated ("masked") | The first 16 bytes of every packet (type, indices, data counter) masked with a keyed hash, so the contents cannot be matched without the key; handshakes and data packets get random lengths; the format is bound into the handshake, so it cannot be switched on the path. Timing stays visible (see Limitations) |

The obfuscated format only works between peers that both run this driver (or
an implementation of the spec below).

## Detecting obfuscation support (apps)

Peer attributes only appear when a peer exists, so use the device-level
attribute, which is present even with zero peers:

| Signal | Where | Meaning |
|--------|-------|---------|
| `WGDEVICE_A_OBFUSCATION_SUPPORT == 1` | GET_DEVICE dump on any `wg*` interface | Kernel supports the obfuscation UAPI |
| `/sys/module/wireguard/version` contains `+obf` | sysfs | Fallback, e.g. `1.0.0+obf1` |
| `WG_GENL_VERSION` | still `1` | Unchanged; do not use for feature detection |

**App probe flow:**

1. Create the interface (`ip link add wg0 type wireguard` or the VpnService
   equivalent).
2. Send `WG_CMD_GET_DEVICE` and read the **first** reply message.
3. If `WGDEVICE_A_OBFUSCATION_SUPPORT` (ID 9) is `1`, offer obfuscation.
4. If it is absent, treat the kernel as stock WireGuard.

Never send `WGDEVICE_A_OBFUSCATION_SUPPORT` on SET (`-EINVAL`).

---

## Configuration (UAPI)

Vendor netlink attributes (see `include/uapi/linux/wireguard.h`):

| Attribute | ID | SET | GET |
|-----------|----|-----|-----|
| `WGDEVICE_A_OBFUSCATION_SUPPORT` | 9 | — (`-EINVAL`) | u8 `1` (first dump message only) |
| `WGDEVICE_A_OBFUSCATION_KEY` | 10 | 32 bytes; all zeros removes it | 32 bytes, only if set (first dump message only) |
| `WGPEER_A_OBFUSCATION` | 11 | u8 `0` or `1` (anything else: `-EINVAL`, nothing is changed) | u8, only if configured |
| `WGPEER_A_OBFUSCATION_FORMAT` | 12 | — (read-only) | u8 format enum |

Format values (`wgpeer_obfuscation_format`), the format used for sending:

- `WGPEER_OBFUSCATION_FORMAT_STANDARD` (1)
- `WGPEER_OBFUSCATION_FORMAT_OBFUSCATED` (2)

A reactive peer reads as `STANDARD` until it has learned otherwise.
`WGPEER_OBFUSCATION_FORMAT_UNKNOWN` (0) is reserved and never reported.

### Shared secret (optional)

`WGDEVICE_A_OBFUSCATION_KEY` is an optional 32-byte secret on the interface.
It is mixed into the keys that mask packets in both directions, so the
interfaces at **both ends** must have the same value: set it on the server's
interface and on each client's interface. Without it, the masks are derived
from the public keys alone.

The secret belongs to the interface rather than to a peer, because the server
has to unmask a handshake before it knows which client sent it. To use servers
with different secrets from one phone, give each server its own interface.

If the secret is set on only one end, or differs, obfuscated packets cannot be
unmasked and the peers do not connect. Standard-format traffic is not affected.

### Client (configured format)

Turn obfuscation on for the server peer:

```
wg set <iface> peer <server_pubkey> obfuscation 1
```

Netlink: include `WGPEER_A_OBFUSCATION = 1` (or `0` to force standard packets).
The configured value controls what is sent, whatever was received.

A peer configured to `1` only takes part in obfuscated handshakes. If the other
side starts a standard handshake, it does not answer and starts an obfuscated
handshake of its own instead; because of WireGuard's handshake rate limit this
can take up to 5 seconds when it handshaked just before. A peer configured to
`0` does the same with obfuscated handshakes.

Changing the value ends the current session, so the next packet starts a new
handshake in the new format.

### Server (reactive mode)

**Omit** `WGPEER_A_OBFUSCATION` for each client peer. A reactive peer accepts
both formats and answers in the format of what it last received from that
peer, after authentication (handshake after Noise validation, data after
decryption and the replay check). Each client is independent.

A newly created peer entry has learned nothing yet. If the server is the side
that starts the first handshake with it, that handshake goes out in standard
format. A client configured to `1` refuses it and starts an obfuscated
handshake, which the server then follows, but the one standard packet is
visible on the wire. Where every client obfuscates, the server's peers can be
configured too instead of left reactive.

### Peer state (`drivers/net/wireguard/peer.h`, `noise.h`)

| Field | Meaning |
|-------|---------|
| `peer->obfuscation_configured` | `WGPEER_A_OBFUSCATION` was set |
| `peer->obfuscation_outbound` | The configured format (on/off) |
| `peer->obfuscation_learned` | Reactive: format of the last authenticated packet |
| `peer->obf_key` | Masks packets sent to this peer |
| `handshake->obf_masked`, `keypair->obf_masked` | The handshake, and the session it creates, are obfuscated |

`wg_obf_peer_masked()` picks the format for a new handshake: the configured
one, otherwise the learned one. Data follows the session it belongs to.

`wg down` does not touch these fields.

---

## Packet format (network)

Both formats carry the standard WireGuard messages unchanged; only the
encoding on the wire differs.

### Standard (0)

Upstream WireGuard. The first 4 bytes are the message type (1 initiation,
2 response, 3 cookie reply, 4 data) as a little-endian 32-bit value, so bytes
1–3 are zero.

### Obfuscated (1)

**Keys.** Each side derives a 128-bit SipHash key from a static public key and
the optional shared secret:

```
K(pub) = first 16 bytes of BLAKE2s-256("mask-key" || pub)
         keyed with the 32-byte secret when one is set, unkeyed otherwise,
         read as two little-endian 64-bit words k0, k1
```

A message is masked with **K(receiver's public key)**. The one exception is a
cookie reply, which goes to a sender that has not been identified yet: it is
masked with **K(cookie sender's own public key)**, which the receiver knows
because it is the peer it was trying to reach.

**Mask.** Bytes 0–15 of the message are XORed with a 16-byte mask computed from
bytes 16–31 (the sample), which are always unpredictable (ephemeral key, nonce
or ciphertext):

```
mask[0..8)  = LE64(SipHash-2-4(k0, k1, sample || LE64(0)))
mask[8..16) = LE64(SipHash-2-4(k0, k1, sample || LE64(1)))
```

For a cookie reply, mask bytes 4–7 are zero, so its receiver index stays
readable: the receiver looks the index up among its own pending handshakes and
sessions to find the peer and with it the key.

**Handshake messages.** The message is built and its MACs are computed as
usual. In an initiation and a response, the top bit of the last byte of the
ephemeral public key (byte 39 of an initiation, byte 43 of a response) is then
set to a random value; it is always 0 in a real key. `random(0..255)` random
bytes are appended, then the mask is applied.

**Data messages.** Instead of WireGuard's padding to a multiple of 16 bytes,
the plaintext gets `random(0..64)` zero bytes of padding, never past the
interface MTU. The packet is encrypted as usual, then the mask is applied; the
sample is the first 16 bytes of ciphertext. A keepalive is padded the same
way, so a decrypted plaintext whose first byte is below `0x10` (no IP version)
is a keepalive.

**Handshake binding.** Both sides mix the 8 ASCII bytes `mask-hs-` into the
handshake hash right after the responder's static public key, that is right
after `h = HASH(h || S_pub_r)` and before the ephemeral key is mixed in. An
obfuscated initiation can therefore only be answered by an obfuscated response,
and a handshake changed into the other format on the way fails. A session
created by an obfuscated handshake only sends and accepts obfuscated data; a
standard session only standard data.

**Receiving.** A message whose first 4 bytes are a standard header (type 1–4,
bytes 1–3 zero) with the standard length is standard. Otherwise, unmask with
K(own public key) and accept if the result is type 1, 2 or 4 with bytes 1–3
zero and a valid length (handshake: its normal size plus 0–255 bytes; data: at
least 32 bytes). Otherwise, if the length is 64–319, treat bytes 4–7 as a
receiver index; if it belongs to one of our obfuscated handshakes or sessions,
unmask with that peer's key (cookie variant) and accept type 3. Then cut the
appended bytes off a handshake, clear the ephemeral key's top bit, and continue
with the standard message.

**Test vectors** (also checked by the in-kernel self-test):

```
public key   00 01 02 .. 1f
sample       a0 a1 a2 .. af
data message 04000000 11223344 0500000000000000 | a0a1..af

without a secret
  K          k0 = 0xdf8274b472fe767b, k1 = 0xc489316d5dc67351
  mask       e458f62e4e3b6f19 4804953cc9678a77
  cookie     e458f62e00000000 4804953cc9678a77
  data       e058f62e5f195c5d 4d04953cc9678a77 | a0a1..af

with the secret 40 41 42 .. 5f
  K          k0 = 0xc1ad46c4c6c36b25, k1 = 0xa6c289b4e0712562
  mask       2d155c03ea88e24a aea34b9944375149
```

---

## Tests

In-kernel self-tests live in `drivers/net/wireguard/selftest/obfuscation.c`.
They run once at driver init when `CONFIG_WIREGUARD_DEBUG=y`; a failure stops
WireGuard from loading. They cover:

- Format selection: configured vs reactive, refusal rules, UAPI format
- Key derivation with and without the secret, mask and data message against
  the test vectors above
- Wrap and parse of every handshake type, wrong key, wrong variant, random
  ephemeral top bit
- Header and length validation, standard messages
- Data padding range and MTU limit, keepalive padding detection

Not covered by the self-tests: live UDP between two peers and netlink from
userspace; those were exercised with two network namespaces in an emulator.

---

## Source files

| File | Role |
|------|------|
| `drivers/net/wireguard/obfuscation.c`, `obfuscation.h` | Keys, mask, padding, wrap, parse, format selection |
| `drivers/net/wireguard/noise.c`, `noise.h` | Handshake binding (`mask-hs-`), obfuscated flag on handshake and session |
| `drivers/net/wireguard/send.c` | Encode handshakes, cookie replies and data on TX; data padding |
| `drivers/net/wireguard/receive.c` | Parse before dispatch; refusal rules; session format check; padded keepalives; learn format |
| `drivers/net/wireguard/netlink.c` | Peer GET/SET; device GET/SET of the secret; device GET emits the support attribute; SET rejects it |
| `drivers/net/wireguard/peer.c`, `peer.h` | Per-peer format state and key |
| `drivers/net/wireguard/peerlookup.c`, `peerlookup.h` | Finds the key for an obfuscated cookie reply from its receiver index |
| `drivers/net/wireguard/device.c`, `device.h` | Device key and secret, follow the private key and the secret |
| `drivers/net/wireguard/queueing.h` | Received format in the packet control block |
| `drivers/net/wireguard/version.h` | Driver version string (`1.0.0+obf1`), generated from `WG_OBFUSCATION_UAPI_VERSION` |
| `include/uapi/linux/wireguard.h` | UAPI attribute definitions |
| `drivers/net/wireguard/selftest/obfuscation.c` | DEBUG self-tests |

---

## Limitations and notes

- **Not encryption:** obfuscation only makes the traffic harder to classify.
  Timing is not hidden.
- **What stays visible:** full-size packets cannot be padded further, so a
  stream of packets at the interface MTU still looks like a tunnel at full
  speed. A cookie reply's receiver index is readable.
- **Who can undo it:** without the shared secret, anyone who knows the
  receiver's public key; packets to the server can be unmasked by anyone who
  has the server's public key. With the secret, they also need the secret.
- **No stock interop:** stock WireGuard only understands the standard format.
- **Userspace:** apps / `wg` must send netlink attribute 11
  (`WGPEER_A_OBFUSCATION`) to configure a client, and attribute 10
  (`WGDEVICE_A_OBFUSCATION_KEY`) to set the secret.
- **Queued packets:** packets already in the encrypt queue keep the format they
  were queued with.
- **Reactive unconfigure:** omitting attribute 11 on SET does not return a
  configured peer to reactive mode; remove and re-add the peer.
- **Attribute numbers:** the vendor attributes take the next free numbers after
  upstream's (device 9 and 10; peer 11 and 12). A future upstream attribute
  would claim the same numbers. `netlink.c` checks them at build time, so a
  merge that shifts them fails to compile instead of silently changing what
  apps talk to.
- **Byte counters:** received handshake bytes are counted with the obfuscated
  length (`obf_wire_len` in the packet control block).

---

## Security

Format learning happens only after authentication (Noise handshake, or data
after decryption and the replay check), and configured peers never learn. An
obfuscated handshake binds its format, so neither the handshake nor the
session it creates can be switched to the standard format on the path. The
data padding is inside the encryption and authenticated. The obfuscation path
allocates nothing for ordinary packets; only when a received buffer is shared
(for example while a packet socket is capturing) is the header copied before
it is rewritten, so other readers of that buffer keep seeing the bytes that
were on the wire. skb and peer lifecycle match upstream WireGuard.

---

# How do I submit patches to Android Common Kernels

1. BEST: Make all of your changes to upstream Linux. If appropriate, backport to the stable releases.
   These patches will be merged automatically in the corresponding common kernels. If the patch is already
   in upstream Linux, post a backport of the patch that conforms to the patch requirements below.
   - Do not send patches upstream that contain only symbol exports. To be considered for upstream Linux,
additions of `EXPORT_SYMBOL_GPL()` require an in-tree modular driver that uses the symbol -- so include
the new driver or changes to an existing driver in the same patchset as the export.
   - When sending patches upstream, the commit message must contain a clear case for why the patch
is needed and beneficial to the community. Enabling out-of-tree drivers or functionality is not
not a persuasive case.

2. LESS GOOD: Develop your patches out-of-tree (from an upstream Linux point-of-view). Unless these are
   fixing an Android-specific bug, these are very unlikely to be accepted unless they have been
   coordinated with kernel-team@android.com. If you want to proceed, post a patch that conforms to the
   patch requirements below.

# Common Kernel patch requirements

- All patches must conform to the Linux kernel coding standards and pass `script/checkpatch.pl`
- Patches shall not break gki_defconfig or allmodconfig builds for arm, arm64, x86, x86_64 architectures
(see  https://source.android.com/setup/build/building-kernels)
- If the patch is not merged from an upstream branch, the subject must be tagged with the type of patch:
`UPSTREAM:`, `BACKPORT:`, `FROMGIT:`, `FROMLIST:`, or `ANDROID:`.
- All patches must have a `Change-Id:` tag (see https://gerrit-review.googlesource.com/Documentation/user-changeid.html)
- If an Android bug has been assigned, there must be a `Bug:` tag.
- All patches must have a `Signed-off-by:` tag by the author and the submitter

Additional requirements are listed below based on patch type

## Requirements for backports from mainline Linux: `UPSTREAM:`, `BACKPORT:`

- If the patch is a cherry-pick from Linux mainline with no changes at all
    - tag the patch subject with `UPSTREAM:`.
    - add upstream commit information with a `(cherry picked from commit ...)` line
    - Example:
        - if the upstream commit message is
```
        important patch from upstream

        This is the detailed description of the important patch

        Signed-off-by: Fred Jones <fred.jones@foo.org>
```
>- then Joe Smith would upload the patch for the common kernel as
```
        UPSTREAM: important patch from upstream

        This is the detailed description of the important patch

        Signed-off-by: Fred Jones <fred.jones@foo.org>

        Bug: 135791357
        Change-Id: I4caaaa566ea080fa148c5e768bb1a0b6f7201c01
        (cherry picked from commit c31e73121f4c1ec41143423ac6ce3ce6dafdcec1)
        Signed-off-by: Joe Smith <joe.smith@foo.org>
```

- If the patch requires any changes from the upstream version, tag the patch with `BACKPORT:`
instead of `UPSTREAM:`.
    - use the same tags as `UPSTREAM:`
    - add comments about the changes under the `(cherry picked from commit ...)` line
    - Example:
```
        BACKPORT: important patch from upstream

        This is the detailed description of the important patch

        Signed-off-by: Fred Jones <fred.jones@foo.org>

        Bug: 135791357
        Change-Id: I4caaaa566ea080fa148c5e768bb1a0b6f7201c01
        (cherry picked from commit c31e73121f4c1ec41143423ac6ce3ce6dafdcec1)
        [joe: Resolved minor conflict in drivers/foo/bar.c ]
        Signed-off-by: Joe Smith <joe.smith@foo.org>
```

## Requirements for other backports: `FROMGIT:`, `FROMLIST:`,

- If the patch has been merged into an upstream maintainer tree, but has not yet
been merged into Linux mainline
    - tag the patch subject with `FROMGIT:`
    - add info on where the patch came from as `(cherry picked from commit <sha1> <repo> <branch>)`. This
must be a stable maintainer branch (not rebased, so don't use `linux-next` for example).
    - if changes were required, use `BACKPORT: FROMGIT:`
    - Example:
        - if the commit message in the maintainer tree is
```
        important patch from upstream

        This is the detailed description of the important patch

        Signed-off-by: Fred Jones <fred.jones@foo.org>
```
>- then Joe Smith would upload the patch for the common kernel as
```
        FROMGIT: important patch from upstream

        This is the detailed description of the important patch

        Signed-off-by: Fred Jones <fred.jones@foo.org>

        Bug: 135791357
        (cherry picked from commit 878a2fd9de10b03d11d2f622250285c7e63deace
         https://git.kernel.org/pub/scm/linux/kernel/git/foo/bar.git test-branch)
        Change-Id: I4caaaa566ea080fa148c5e768bb1a0b6f7201c01
        Signed-off-by: Joe Smith <joe.smith@foo.org>
```


- If the patch has been submitted to LKML, but not accepted into any maintainer tree
    - tag the patch subject with `FROMLIST:`
    - add a `Link:` tag with a link to the submittal on lore.kernel.org
    - add a `Bug:` tag with the Android bug (required for patches not accepted into
a maintainer tree)
    - if changes were required, use `BACKPORT: FROMLIST:`
    - Example:
```
        FROMLIST: important patch from upstream

        This is the detailed description of the important patch

        Signed-off-by: Fred Jones <fred.jones@foo.org>

        Bug: 135791357
        Link: https://lore.kernel.org/lkml/20190619171517.GA17557@someone.com/
        Change-Id: I4caaaa566ea080fa148c5e768bb1a0b6f7201c01
        Signed-off-by: Joe Smith <joe.smith@foo.org>
```

## Requirements for Android-specific patches: `ANDROID:`

- If the patch is fixing a bug to Android-specific code
    - tag the patch subject with `ANDROID:`
    - add a `Fixes:` tag that cites the patch with the bug
    - Example:
```
        ANDROID: fix android-specific bug in foobar.c

        This is the detailed description of the important fix

        Fixes: 1234abcd2468 ("foobar: add cool feature")
        Change-Id: I4caaaa566ea080fa148c5e768bb1a0b6f7201c01
        Signed-off-by: Joe Smith <joe.smith@foo.org>
```

- If the patch is a new feature
    - tag the patch subject with `ANDROID:`
    - add a `Bug:` tag with the Android bug (required for android-specific features)
