/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/stringify.h>
#include <uapi/linux/wireguard.h>

/* The "+obfN" suffix always matches WG_OBFUSCATION_UAPI_VERSION. */
#define WIREGUARD_VERSION "1.0.0+obf" __stringify(WG_OBFUSCATION_UAPI_VERSION)
