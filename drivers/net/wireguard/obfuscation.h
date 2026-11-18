/* SPDX-License-Identifier: GPL-2.0 */
/*
 * WireGuard traffic obfuscation: the first 16 bytes of every message masked
 * with a keyed hash of the next 16, random trailing junk on handshakes and
 * random padding on data messages.
 *
 * WGPEER_A_OBFUSCATION: if set, 0 or 1 forces outbound wire format; if omitted,
 * the peer stays in reactive mode (match remote from RX). New peers default to
 * reactive.
 */

#ifndef _WG_OBFUSCATION_H
#define _WG_OBFUSCATION_H

#include "messages.h"

#include <linux/siphash.h>
#include <linux/skbuff.h>
#include <linux/types.h>

struct wg_device;
struct wg_peer;

/* Fixed trailing junk range on handshakes: 0..WG_OBF_SUFFIX_MAX bytes. */
#define WG_OBF_SUFFIX_MAX 255

#define WG_OBF_DATA_PAD_MAX 64
#define WG_OBF_HDR_LEN 16
#define WG_OBF_SAMPLE_LEN 16
#define WG_OBF_SECRET_LEN NOISE_SYMMETRIC_KEY_LEN

void wg_obf_derive_key(siphash_key_t *key,
		       const u8 public_key[NOISE_PUBLIC_KEY_LEN],
		       const u8 *secret);
void wg_obf_update_keys(struct wg_device *wg);
bool wg_obf_device_key(struct wg_device *wg, siphash_key_t *key);
void wg_obf_peer_key(struct wg_peer *peer, siphash_key_t *key);

void wg_obf_mask(u8 *hdr, const u8 *sample, const siphash_key_t *key,
		 bool cookie);
void wg_obf_mask_data(struct sk_buff *skb, const siphash_key_t *key);
unsigned int wg_obf_data_padding(const struct sk_buff *skb);
bool wg_obf_is_padding(struct sk_buff *skb);

bool wg_obf_peer_masked(const struct wg_peer *peer);
bool wg_obf_peer_refuses(const struct wg_peer *peer, bool masked);
void wg_obf_peer_note_rx_format(struct wg_peer *peer, bool masked);

u8 wg_obf_peer_uapi_format(const struct wg_peer *peer);

u8 wg_obf_parse_message(struct wg_device *wg, struct sk_buff *skb);

size_t wg_obf_wrap_handshake(void *dst, size_t dst_cap, const void *src,
			     size_t src_len, u8 msg_type,
			     const siphash_key_t *key);

#ifdef DEBUG
bool wg_obfuscation_selftest(void);
#endif

#endif /* _WG_OBFUSCATION_H */
