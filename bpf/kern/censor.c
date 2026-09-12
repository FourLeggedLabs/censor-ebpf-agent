#include "vmlinux_stub.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define AF_INET 2
#define AF_INET6 10

#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif
#ifndef BPF_ANY
#define BPF_ANY 0
#endif

struct lpm_v4_key {
	__u32 prefixlen;
	__u32 addr;
};

struct lpm_v6_key {
	__u32 prefixlen;
	__u32 addr[4];
};

struct event {
	__u32 pid;
	__u32 dst_v4;
	__u32 dst_v6[4];
	__u16 dport;
	__u8 proto;
	__u8 allowed;
	__u8 family; /* 4 or 6 */
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16384);
	__type(key, struct lpm_v4_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allow_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16384);
	__type(key, struct lpm_v6_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allow_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, __u32);
} sock_pid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void emit(__u32 pid, __u32 dst4, const __u32 dst6[4], __u16 dport,
				 __u8 proto, __u8 allowed, __u8 family)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->pid = pid;
	e->dst_v4 = dst4;
	if (dst6) {
		e->dst_v6[0] = dst6[0];
		e->dst_v6[1] = dst6[1];
		e->dst_v6[2] = dst6[2];
		e->dst_v6[3] = dst6[3];
	} else {
		e->dst_v6[0] = e->dst_v6[1] = e->dst_v6[2] = e->dst_v6[3] = 0;
	}
	e->dport = dport;
	e->proto = proto;
	e->allowed = allowed;
	e->family = family;
	e->pad[0] = e->pad[1] = e->pad[2] = 0;
	bpf_ringbuf_submit(e, 0);
}

static __always_inline int lookup_allow_v4(__u32 dst_be)
{
	struct lpm_v4_key key = {.prefixlen = 32, .addr = dst_be};
	return bpf_map_lookup_elem(&allow_v4, &key) != 0;
}

static __always_inline int lookup_allow_v6(const __u32 addr[4])
{
	struct lpm_v6_key key = {};
	key.prefixlen = 128;
	key.addr[0] = addr[0];
	key.addr[1] = addr[1];
	key.addr[2] = addr[2];
	key.addr[3] = addr[3];
	return bpf_map_lookup_elem(&allow_v6, &key) != 0;
}

static __always_inline __u32 current_pid_for_skb(struct __sk_buff *skb)
{
	__u64 cookie = bpf_get_socket_cookie(skb);
	__u32 *p = bpf_map_lookup_elem(&sock_pid, &cookie);
	return p ? *p : 0;
}

static __always_inline int handle_v4(struct __sk_buff *skb, void *data, void *data_end)
{
	struct ethhdr *eth = data;
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;
	if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	__u32 ihl = ip->ihl;
	if (ihl < 5)
		return TC_ACT_OK;
	__u8 *l4 = (__u8 *)ip + (ihl * 4);
	if ((void *)(l4 + 4) > data_end)
		return TC_ACT_OK;
	__u16 dport = ((__u16)l4[2] << 8) | l4[3];

	__u32 cfg_key = 0;
	__u32 *audit = bpf_map_lookup_elem(&config, &cfg_key);
	__u32 audit_mode = audit ? *audit : 1;
	__u32 pid = current_pid_for_skb(skb);
	int allowed = lookup_allow_v4(ip->daddr);
	emit(pid, ip->daddr, (const __u32 *)0, dport, ip->protocol, allowed ? 1 : 0, 4);
	if (!allowed && !audit_mode)
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

static __always_inline int handle_v6(struct __sk_buff *skb, void *data, void *data_end)
{
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		return TC_ACT_OK;

	/* Allow ICMPv6 and IPv6 multicast. */
	__u8 nexthdr = ip6->nexthdr;
	if (nexthdr == IPPROTO_ICMPV6)
		return TC_ACT_OK;
	if (ip6->daddr.in6_u.u6_addr8[0] == 0xff)
		return TC_ACT_OK;
	if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP)
		return TC_ACT_OK;

	__u8 *l4 = (__u8 *)(ip6 + 1);
	if ((void *)(l4 + 4) > data_end)
		return TC_ACT_OK;
	__u16 dport = ((__u16)l4[2] << 8) | l4[3];

	__u32 addr[4];
	__builtin_memcpy(addr, ip6->daddr.in6_u.u6_addr32, 16);

	__u32 cfg_key = 0;
	__u32 *audit = bpf_map_lookup_elem(&config, &cfg_key);
	__u32 audit_mode = audit ? *audit : 1;
	__u32 pid = current_pid_for_skb(skb);
	int allowed = lookup_allow_v6(addr);
	emit(pid, 0, addr, dport, nexthdr, allowed ? 1 : 0, 6);
	if (!allowed && !audit_mode)
		return TC_ACT_SHOT;
	return TC_ACT_OK;
}

SEC("tc")
int censor_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto == bpf_htons(ETH_P_IP))
		return handle_v4(skb, data, data_end);
	if (eth->h_proto == bpf_htons(ETH_P_IPV6))
		return handle_v6(skb, data, data_end);
	return TC_ACT_OK;
}

SEC("cgroup/connect4")
int censor_connect4(struct bpf_sock_addr *ctx)
{
	__u64 cookie = bpf_get_socket_cookie(ctx);
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&sock_pid, &cookie, &pid, BPF_ANY);
	return 1;
}

SEC("cgroup/connect6")
int censor_connect6(struct bpf_sock_addr *ctx)
{
	__u64 cookie = bpf_get_socket_cookie(ctx);
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&sock_pid, &cookie, &pid, BPF_ANY);
	return 1;
}
