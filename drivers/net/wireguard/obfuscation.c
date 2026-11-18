// SPDX-License-Identifier: GPL-2.0
/*
 * WireGuard traffic obfuscation.
 */

#include "obfuscation.h"
#include "device.h"
#include "peer.h"
#include "peerlookup.h"
#include "queueing.h"

#include <asm/unaligned.h>
#include <crypto/blake2s.h>
#include <linux/build_bug.h>
#include <linux/random.h>
#include <linux/seqlock.h>
#include <linux/siphash.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <uapi/linux/wireguard.h>

#define OBF_INITIATION_TOP \
	(offsetof(struct message_handshake_initiation, unencrypted_ephemeral) + \
	 NOISE_PUBLIC_KEY_LEN - 1)
#define OBF_RESPONSE_TOP \
	(offsetof(struct message_handshake_response, unencrypted_ephemeral) + \
	 NOISE_PUBLIC_KEY_LEN - 1)

static_assert(WG_OBF_HDR_LEN + WG_OBF_SAMPLE_LEN <= MESSAGE_MINIMUM_LENGTH);
static_assert(sizeof(struct message_data) == WG_OBF_HDR_LEN);
static_assert(WG_OBF_HDR_LEN + WG_OBF_SAMPLE_LEN <= OBF_INITIATION_TOP);
static_assert(WG_OBF_HDR_LEN + WG_OBF_SAMPLE_LEN <= OBF_RESPONSE_TOP);

static size_t obf_handshake_base_len(u8 msg_type)
{
	switch (msg_type) {
	case MESSAGE_HANDSHAKE_INITIATION:
		return sizeof(struct message_handshake_initiation);
	case MESSAGE_HANDSHAKE_RESPONSE:
		return sizeof(struct message_handshake_response);
	case MESSAGE_HANDSHAKE_COOKIE:
		return sizeof(struct message_handshake_cookie);
	default:
		return 0;
	}
}

static size_t obf_ephemeral_top(u8 msg_type)
{
	switch (msg_type) {
	case MESSAGE_HANDSHAKE_INITIATION:
		return OBF_INITIATION_TOP;
	case MESSAGE_HANDSHAKE_RESPONSE:
		return OBF_RESPONSE_TOP;
	default:
		return 0;
	}
}

static bool obf_header_is_standard(const struct message_header *hdr)
{
	return !(le32_to_cpu(hdr->type) & ~0xffU);
}

void wg_obf_derive_key(siphash_key_t *key,
		       const u8 public_key[NOISE_PUBLIC_KEY_LEN],
		       const u8 *secret)
{
	static const u8 label[8] = "mask-key";
	struct blake2s_state blake;
	u8 out[BLAKE2S_HASH_SIZE];

	if (secret)
		blake2s_init_key(&blake, BLAKE2S_HASH_SIZE, secret,
				 WG_OBF_SECRET_LEN);
	else
		blake2s_init(&blake, BLAKE2S_HASH_SIZE);
	blake2s_update(&blake, label, sizeof(label));
	blake2s_update(&blake, public_key, NOISE_PUBLIC_KEY_LEN);
	blake2s_final(&blake, out);
	key->key[0] = get_unaligned_le64(out);
	key->key[1] = get_unaligned_le64(out + 8);
	memzero_explicit(out, sizeof(out));
}

void wg_obf_update_keys(struct wg_device *wg)
{
	const u8 *secret = wg->obf_has_secret ? wg->obf_secret : NULL;
	const bool valid = wg->static_identity.has_identity;
	siphash_key_t key = {};
	struct wg_peer *peer;

	if (valid)
		wg_obf_derive_key(&key, wg->static_identity.static_public,
				  secret);
	write_seqlock_bh(&wg->obf_key_lock);
	wg->obf_key = key;
	wg->obf_key_valid = valid;
	write_sequnlock_bh(&wg->obf_key_lock);

	list_for_each_entry(peer, &wg->peer_list, peer_list) {
		wg_obf_derive_key(&key, peer->handshake.remote_static, secret);
		write_seqlock_bh(&wg->obf_key_lock);
		peer->obf_key = key;
		write_sequnlock_bh(&wg->obf_key_lock);
	}
	memzero_explicit(&key, sizeof(key));
}

bool wg_obf_device_key(struct wg_device *wg, siphash_key_t *key)
{
	unsigned int seq;
	bool valid;

	do {
		seq = read_seqbegin(&wg->obf_key_lock);
		*key = wg->obf_key;
		valid = wg->obf_key_valid;
	} while (read_seqretry(&wg->obf_key_lock, seq));
	return valid;
}

void wg_obf_peer_key(struct wg_peer *peer, siphash_key_t *key)
{
	seqlock_t *lock = &peer->device->obf_key_lock;
	unsigned int seq;

	do {
		seq = read_seqbegin(lock);
		*key = peer->obf_key;
	} while (read_seqretry(lock, seq));
}

void wg_obf_mask(u8 *hdr, const u8 *sample, const siphash_key_t *key,
		 bool cookie)
{
	const u64 s0 = get_unaligned_le64(sample);
	const u64 s1 = get_unaligned_le64(sample + 8);
	u8 mask[WG_OBF_HDR_LEN];
	unsigned int i;

	put_unaligned_le64(siphash_3u64(s0, s1, 0, key), mask);
	put_unaligned_le64(siphash_3u64(s0, s1, 1, key), mask + 8);
	if (cookie)
		memset(mask + 4, 0, 4);
	for (i = 0; i < sizeof(mask); ++i)
		hdr[i] ^= mask[i];
}

void wg_obf_mask_data(struct sk_buff *skb, const siphash_key_t *key)
{
	u8 sample[WG_OBF_SAMPLE_LEN];

	if (WARN_ON_ONCE(skb_copy_bits(skb, WG_OBF_HDR_LEN, sample,
				       sizeof(sample))))
		return;
	wg_obf_mask(skb->data, sample, key, false);
}

unsigned int wg_obf_data_padding(const struct sk_buff *skb)
{
	const unsigned int len = skb->len, mtu = PACKET_CB(skb)->mtu;
	unsigned int target = len + get_random_u32() % (WG_OBF_DATA_PAD_MAX + 1);

	if (mtu && target > mtu)
		target = max(len, mtu);
	return target - len;
}

bool wg_obf_is_padding(struct sk_buff *skb)
{
	u8 first;

	return !skb_copy_bits(skb, 0, &first, 1) && !(first >> 4);
}

bool wg_obf_peer_masked(const struct wg_peer *peer)
{
	if (READ_ONCE(peer->obfuscation_configured))
		return READ_ONCE(peer->obfuscation_outbound);
	return READ_ONCE(peer->obfuscation_learned);
}

bool wg_obf_peer_refuses(const struct wg_peer *peer, bool masked)
{
	return READ_ONCE(peer->obfuscation_configured) &&
	       READ_ONCE(peer->obfuscation_outbound) != masked;
}

void wg_obf_peer_note_rx_format(struct wg_peer *peer, bool masked)
{
	if (READ_ONCE(peer->obfuscation_configured))
		return;
	if (READ_ONCE(peer->obfuscation_learned) != masked)
		WRITE_ONCE(peer->obfuscation_learned, masked);
}

u8 wg_obf_peer_uapi_format(const struct wg_peer *peer)
{
	return wg_obf_peer_masked(peer) ?
		WGPEER_OBFUSCATION_FORMAT_OBFUSCATED :
		WGPEER_OBFUSCATION_FORMAT_STANDARD;
}

size_t wg_obf_wrap_handshake(void *dst, size_t dst_cap, const void *src,
			     size_t src_len, u8 msg_type,
			     const siphash_key_t *key)
{
	const size_t suffix_len = get_random_u32() % (WG_OBF_SUFFIX_MAX + 1);
	const size_t top = obf_ephemeral_top(msg_type);
	const size_t total = src_len + suffix_len;
	u8 *out = dst;

	if (unlikely(total > dst_cap || (top && top >= src_len)))
		return 0;
	memcpy(out, src, src_len);
	if (suffix_len)
		get_random_bytes(out + src_len, suffix_len);
	if (top)
		out[top] |= get_random_u32() & 0x80;
	wg_obf_mask(out, out + WG_OBF_HDR_LEN, key,
		    msg_type == MESSAGE_HANDSHAKE_COOKIE);
	return total;
}

static bool obf_standard_message_valid(struct sk_buff *skb, u8 msg_type)
{
	/* Same checks as upstream validate_header_len() for standard wire. */
	switch (msg_type) {
	case MESSAGE_DATA:
		return skb->len >= MESSAGE_MINIMUM_LENGTH;
	case MESSAGE_HANDSHAKE_INITIATION:
		return skb->len == sizeof(struct message_handshake_initiation);
	case MESSAGE_HANDSHAKE_RESPONSE:
		return skb->len == sizeof(struct message_handshake_response);
	case MESSAGE_HANDSHAKE_COOKIE:
		return skb->len == sizeof(struct message_handshake_cookie);
	default:
		return false;
	}
}

static u8 obf_masked_check(const u8 *plain, size_t len)
{
	const u32 type = get_unaligned_le32(plain);
	size_t base;

	if (type == MESSAGE_DATA)
		return len >= MESSAGE_MINIMUM_LENGTH ? MESSAGE_DATA : 0;
	if (type < MESSAGE_HANDSHAKE_INITIATION || type > MESSAGE_DATA)
		return 0;
	base = obf_handshake_base_len(type);
	if (len < base || len > base + WG_OBF_SUFFIX_MAX)
		return 0;
	return type;
}

static u8 obf_masked_finish(struct sk_buff *skb, u8 msg_type, const u8 *plain)
{
	const size_t top = obf_ephemeral_top(msg_type);

	if (msg_type != MESSAGE_DATA &&
	    pskb_trim(skb, obf_handshake_base_len(msg_type)))
		return 0;
	if (skb_ensure_writable(skb, top ? top + 1 : WG_OBF_HDR_LEN))
		return 0;
	memcpy(skb->data, plain, WG_OBF_HDR_LEN);
	if (top)
		skb->data[top] &= 0x7f;
	PACKET_CB(skb)->obf_masked = true;
	return msg_type;
}

static u8 obf_parse_masked(struct wg_device *wg, struct sk_buff *skb)
{
	u8 hdr[WG_OBF_HDR_LEN], plain[WG_OBF_HDR_LEN];
	u8 sample[WG_OBF_SAMPLE_LEN];
	siphash_key_t key;
	__le32 index;
	u8 msg_type;

	if (!wg || skb->len < sizeof(hdr) + sizeof(sample) ||
	    skb_copy_bits(skb, 0, hdr, sizeof(hdr)) ||
	    skb_copy_bits(skb, sizeof(hdr), sample, sizeof(sample)))
		return 0;

	if (wg_obf_device_key(wg, &key)) {
		memcpy(plain, hdr, sizeof(plain));
		wg_obf_mask(plain, sample, &key, false);
		msg_type = obf_masked_check(plain, skb->len);
		if (msg_type && msg_type != MESSAGE_HANDSHAKE_COOKIE)
			return obf_masked_finish(skb, msg_type, plain);
	}

	if (skb->len < sizeof(struct message_handshake_cookie) ||
	    skb->len > sizeof(struct message_handshake_cookie) + WG_OBF_SUFFIX_MAX)
		return 0;
	memcpy(&index, hdr + 4, sizeof(index));
	if (!wg_index_hashtable_obf_key(wg->index_hashtable, index, &key))
		return 0;
	memcpy(plain, hdr, sizeof(plain));
	wg_obf_mask(plain, sample, &key, true);
	if (obf_masked_check(plain, skb->len) != MESSAGE_HANDSHAKE_COOKIE)
		return 0;
	return obf_masked_finish(skb, MESSAGE_HANDSHAKE_COOKIE, plain);
}

u8 wg_obf_parse_message(struct wg_device *wg, struct sk_buff *skb)
{
	struct message_header *hdr = (struct message_header *)skb->data;
	u8 msg_type;

	/* Replaces upstream validate_header_len(); supports obfuscated wire too. */
	if (unlikely(skb->len < sizeof(*hdr)))
		return 0;

	PACKET_CB(skb)->obf_masked = false;
	PACKET_CB(skb)->obf_wire_len = 0;

	if (obf_header_is_standard(hdr)) {
		msg_type = le32_to_cpu(hdr->type);
		if (obf_standard_message_valid(skb, msg_type))
			return msg_type;
	}

	PACKET_CB(skb)->obf_wire_len = skb->len;
	msg_type = obf_parse_masked(wg, skb);
	if (!msg_type)
		PACKET_CB(skb)->obf_wire_len = 0;
	return msg_type;
}

#include "selftest/obfuscation.c"
