#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>
#include <stddef.h>
#include "bpf_helpers.h"

/* compiler workaround */
#define _htonl __builtin_bswap32
#define htons __builtin_bswap16

static inline void set_dst_mac(struct __sk_buff *skb, char *mac)
{
	bpf_skb_store_bytes(skb, 0, mac, ETH_ALEN, 1);
}

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TTL_OFF (ETH_HLEN + offsetof(struct iphdr, ttl))

static inline void set_ip_ttl(struct __sk_buff *skb, __u8 new_ttl)
{
	__u8 old_ttl = load_byte(skb, TTL_OFF);

	bpf_l3_csum_replace(skb, IP_CSUM_OFF, htons(old_ttl << 8), htons(new_ttl << 8), 2);
	bpf_skb_store_bytes(skb, TTL_OFF, &new_ttl, sizeof(new_ttl), 0);
}

SEC("classifier")
int cls_main(struct __sk_buff *skb)
{
	__u8 proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	long *value;

        set_ip_ttl(skb, 64);

	return 0;
}

SEC("action")
int set_ttl(struct __sk_buff *skb)
{
	return TC_ACT_PIPE;
}

char __license[] SEC("license") = "GPL";
