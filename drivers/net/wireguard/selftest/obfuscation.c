// SPDX-License-Identifier: GPL-2.0

#ifdef DEBUG
static struct sk_buff *obf_test_skb(const void *data, size_t len)
{
	struct sk_buff *skb;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return NULL;
	skb_put_data(skb, data, len);
	return skb;
}

static u8 __init obf_test_parse_masked(struct sk_buff *skb,
				       const siphash_key_t *key, bool cookie)
{
	u8 hdr[WG_OBF_HDR_LEN], sample[WG_OBF_SAMPLE_LEN];
	bool is_cookie;
	u8 msg_type;

	PACKET_CB(skb)->obf_masked = false;
	if (skb_copy_bits(skb, 0, hdr, sizeof(hdr)) ||
	    skb_copy_bits(skb, sizeof(hdr), sample, sizeof(sample)))
		return 0;
	wg_obf_mask(hdr, sample, key, cookie);
	msg_type = obf_masked_check(hdr, skb->len);
	is_cookie = msg_type == MESSAGE_HANDSHAKE_COOKIE;
	if (!msg_type || is_cookie != cookie)
		return 0;
	return obf_masked_finish(skb, msg_type, hdr);
}

struct obf_test_msg {
	u8 type;
	size_t len;
};

#define OBF_EXPECT(cond, name) do {					\
		if (!(cond)) {						\
			pr_err("obfuscation self-test " name ": FAIL\n"); \
			success = false;				\
		}							\
	} while (0)

bool __init wg_obfuscation_selftest(void)
{
	static const u8 kat_mask[WG_OBF_HDR_LEN] __initconst = {
		0xe4, 0x58, 0xf6, 0x2e, 0x4e, 0x3b, 0x6f, 0x19,
		0x48, 0x04, 0x95, 0x3c, 0xc9, 0x67, 0x8a, 0x77
	};
	static const u8 kat_mask_secret[WG_OBF_HDR_LEN] __initconst = {
		0x2d, 0x15, 0x5c, 0x03, 0xea, 0x88, 0xe2, 0x4a,
		0xae, 0xa3, 0x4b, 0x99, 0x44, 0x37, 0x51, 0x49
	};
	static const u8 kat_data[WG_OBF_HDR_LEN] __initconst = {
		0xe0, 0x58, 0xf6, 0x2e, 0x5f, 0x19, 0x5c, 0x5d,
		0x4d, 0x04, 0x95, 0x3c, 0xc9, 0x67, 0x8a, 0x77
	};
	static const struct obf_test_msg msgs[] __initconst = {
		{ MESSAGE_HANDSHAKE_INITIATION,
		  sizeof(struct message_handshake_initiation) },
		{ MESSAGE_HANDSHAKE_RESPONSE,
		  sizeof(struct message_handshake_response) },
		{ MESSAGE_HANDSHAKE_COOKIE,
		  sizeof(struct message_handshake_cookie) },
	};
	u8 wire[sizeof(struct message_handshake_initiation) + WG_OBF_SUFFIX_MAX];
	u8 plain[sizeof(struct message_handshake_initiation)];
	u8 hdr16[WG_OBF_HDR_LEN], sample[WG_OBF_SAMPLE_LEN];
	u8 pub[NOISE_PUBLIC_KEY_LEN], secret[WG_OBF_SECRET_LEN];
	u8 data_wire[MESSAGE_MINIMUM_LENGTH];
	unsigned int i, round, pad, top_set, top_clear;
	siphash_key_t key, other_key;
	struct wg_peer *peer;
	struct sk_buff *skb;
	bool success = true;
	size_t len, top;

	peer = kzalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer)
		return false;

	OBF_EXPECT(!wg_obf_peer_masked(peer), "new peer");
	OBF_EXPECT(!wg_obf_peer_refuses(peer, true) &&
		   !wg_obf_peer_refuses(peer, false), "reactive takes both");
	wg_obf_peer_note_rx_format(peer, true);
	OBF_EXPECT(wg_obf_peer_masked(peer), "reactive learns masked");
	OBF_EXPECT(wg_obf_peer_uapi_format(peer) ==
		   WGPEER_OBFUSCATION_FORMAT_OBFUSCATED, "uapi masked");
	wg_obf_peer_note_rx_format(peer, false);
	OBF_EXPECT(!wg_obf_peer_masked(peer), "reactive learns standard");
	OBF_EXPECT(wg_obf_peer_uapi_format(peer) ==
		   WGPEER_OBFUSCATION_FORMAT_STANDARD, "uapi standard");

	peer->obfuscation_configured = true;
	peer->obfuscation_outbound = true;
	wg_obf_peer_note_rx_format(peer, false);
	OBF_EXPECT(wg_obf_peer_masked(peer) && !peer->obfuscation_learned,
		   "configured ignores rx");
	OBF_EXPECT(!wg_obf_peer_refuses(peer, true) &&
		   wg_obf_peer_refuses(peer, false), "configured on refuses");
	peer->obfuscation_outbound = false;
	OBF_EXPECT(!wg_obf_peer_masked(peer), "configured off");
	OBF_EXPECT(wg_obf_peer_refuses(peer, true) &&
		   !wg_obf_peer_refuses(peer, false), "configured off refuses");

	for (i = 0; i < sizeof(pub); ++i)
		pub[i] = i;
	for (i = 0; i < sizeof(secret); ++i)
		secret[i] = 0x40 + i;
	for (i = 0; i < sizeof(sample); ++i)
		sample[i] = 0xa0 + i;

	wg_obf_derive_key(&key, pub, NULL);
	OBF_EXPECT(key.key[0] == 0xdf8274b472fe767bULL &&
		   key.key[1] == 0xc489316d5dc67351ULL, "key derivation");
	wg_obf_derive_key(&other_key, pub, secret);
	OBF_EXPECT(other_key.key[0] == 0xc1ad46c4c6c36b25ULL &&
		   other_key.key[1] == 0xa6c289b4e0712562ULL,
		   "key derivation with secret");

	memset(hdr16, 0, sizeof(hdr16));
	wg_obf_mask(hdr16, sample, &other_key, false);
	OBF_EXPECT(!memcmp(hdr16, kat_mask_secret, sizeof(hdr16)),
		   "mask with secret");
	memset(hdr16, 0, sizeof(hdr16));
	wg_obf_mask(hdr16, sample, &key, false);
	OBF_EXPECT(!memcmp(hdr16, kat_mask, sizeof(hdr16)), "mask");
	wg_obf_mask(hdr16, sample, &key, false);
	for (i = 0; i < sizeof(hdr16); ++i)
		OBF_EXPECT(!hdr16[i], "mask is its own inverse");
	wg_obf_mask(hdr16, sample, &key, true);
	OBF_EXPECT(!memcmp(hdr16, kat_mask, 4) &&
		   get_unaligned_le32(hdr16 + 4) == 0 &&
		   !memcmp(hdr16 + 8, kat_mask + 8, 8), "cookie mask");

	memset(data_wire, 0, sizeof(data_wire));
	put_unaligned_le32(MESSAGE_DATA, data_wire);
	put_unaligned_le32(0x44332211, data_wire + 4);
	put_unaligned_le64(5, data_wire + 8);
	memcpy(data_wire + WG_OBF_HDR_LEN, sample, sizeof(sample));
	skb = obf_test_skb(data_wire, sizeof(data_wire));
	if (!skb) {
		success = false;
		goto out;
	}
	wg_obf_mask_data(skb, &key);
	OBF_EXPECT(!memcmp(skb->data, kat_data, sizeof(kat_data)),
		   "data message");
	OBF_EXPECT(obf_test_parse_masked(skb, &key, false) == MESSAGE_DATA &&
		   PACKET_CB(skb)->obf_masked &&
		   !memcmp(skb->data, data_wire, sizeof(data_wire)),
		   "data parse");
	consume_skb(skb);

	for (i = 0; i < ARRAY_SIZE(msgs); ++i) {
		const bool cookie = msgs[i].type == MESSAGE_HANDSHAKE_COOKIE;

		memset(plain, 0x5a, sizeof(plain));
		put_unaligned_le32(msgs[i].type, plain);
		top = obf_ephemeral_top(msgs[i].type);
		top_set = 0;
		top_clear = 0;
		for (round = 0; round < 64; ++round) {
			len = wg_obf_wrap_handshake(wire, sizeof(wire), plain,
						    msgs[i].len, msgs[i].type,
						    &key);
			OBF_EXPECT(len >= msgs[i].len &&
				   len <= msgs[i].len + WG_OBF_SUFFIX_MAX,
				   "wrap length");
			if (top && (wire[top] & 0x80))
				++top_set;
			else
				++top_clear;
			skb = obf_test_skb(wire, len);
			if (!skb) {
				success = false;
				goto out;
			}
			OBF_EXPECT(!obf_test_parse_masked(skb, &other_key,
							  cookie),
				   "wrong key");
			OBF_EXPECT(!obf_test_parse_masked(skb, &key, !cookie),
				   "wrong variant");
			OBF_EXPECT(obf_test_parse_masked(skb, &key, cookie) ==
				   msgs[i].type && skb->len == msgs[i].len &&
				   PACKET_CB(skb)->obf_masked &&
				   !memcmp(skb->data, plain, msgs[i].len),
				   "wrap and parse");
			consume_skb(skb);
		}
		OBF_EXPECT(!top || (top_set && top_clear),
			   "ephemeral top bit is random");

		skb = obf_test_skb(plain, msgs[i].len);
		if (!skb) {
			success = false;
			goto out;
		}
		OBF_EXPECT(wg_obf_parse_message(NULL, skb) == msgs[i].type &&
			   !PACKET_CB(skb)->obf_masked, "standard parse");
		consume_skb(skb);
	}

	memset(hdr16, 0, sizeof(hdr16));
	OBF_EXPECT(!obf_masked_check(hdr16, 148), "type 0");
	put_unaligned_le32(MESSAGE_DATA + 1, hdr16);
	OBF_EXPECT(!obf_masked_check(hdr16, 148), "type 5");
	put_unaligned_le32(MESSAGE_DATA | 0x100, hdr16);
	OBF_EXPECT(!obf_masked_check(hdr16, 148), "reserved bytes");
	put_unaligned_le32(MESSAGE_HANDSHAKE_RESPONSE, hdr16);
	len = sizeof(struct message_handshake_response);
	OBF_EXPECT(!obf_masked_check(hdr16, len - 1) &&
		   obf_masked_check(hdr16, len) &&
		   obf_masked_check(hdr16, len + WG_OBF_SUFFIX_MAX) &&
		   !obf_masked_check(hdr16, len + WG_OBF_SUFFIX_MAX + 1),
		   "handshake length");
	put_unaligned_le32(MESSAGE_DATA, hdr16);
	OBF_EXPECT(!obf_masked_check(hdr16, MESSAGE_MINIMUM_LENGTH - 1) &&
		   obf_masked_check(hdr16, MESSAGE_MINIMUM_LENGTH) &&
		   obf_masked_check(hdr16, 1500), "data length");

	skb = alloc_skb(1600, GFP_KERNEL);
	if (!skb) {
		success = false;
		goto out;
	}
	skb_put_zero(skb, 1500);
	for (round = 0; round < 64; ++round) {
		skb_trim(skb, 40);
		PACKET_CB(skb)->mtu = 1420;
		pad = wg_obf_data_padding(skb);
		OBF_EXPECT(pad <= WG_OBF_DATA_PAD_MAX, "data padding range");
		PACKET_CB(skb)->mtu = 60;
		OBF_EXPECT(40 + wg_obf_data_padding(skb) <= 60,
			   "data padding stays within the mtu");
		skb_put_zero(skb, 1380);
		PACKET_CB(skb)->mtu = 1420;
		OBF_EXPECT(!wg_obf_data_padding(skb), "no padding at the mtu");
	}
	skb_trim(skb, 16);
	OBF_EXPECT(wg_obf_is_padding(skb), "zero padding is padding");
	skb->data[0] = 0x45;
	OBF_EXPECT(!wg_obf_is_padding(skb), "ipv4 is not padding");
	skb->data[0] = 0x60;
	OBF_EXPECT(!wg_obf_is_padding(skb), "ipv6 is not padding");
	consume_skb(skb);

out:
	kfree(peer);
	if (success)
		pr_info("obfuscation self-tests: pass\n");
	return success;
}
#endif
