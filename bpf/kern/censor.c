#include "vmlinux_stub.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

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

struct event {
	__u32 pid;
	__u32 dst;
	__u16 dport;
	__u8 proto;
	__u8 allowed;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16384);
	__type(key, struct lpm_v4_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allow_v4 SEC(".maps");

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

static __always_inline void emit(__u32 pid, __u32 dst, __u16 dport, __u8 proto, __u8 allowed)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	e->pid = pid;
	e->dst = dst;
	e->dport = dport;
	e->proto = proto;
	e->allowed = allowed;
	bpf_ringbuf_submit(e, 0);
}

static __always_inline int lookup_allow(__u32 dst_be)
{
	struct lpm_v4_key key = {.prefixlen = 32, .addr = dst_be};
	__u8 *v = bpf_map_lookup_elem(&allow_v4, &key);
	return v != 0;
}

SEC("tc")
int censor_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

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

	__u64 cookie = bpf_get_socket_cookie(skb);
	__u32 pid = 0;
	__u32 *p = bpf_map_lookup_elem(&sock_pid, &cookie);
	if (p)
		pid = *p;

	int allowed = lookup_allow(ip->daddr);
	emit(pid, ip->daddr, dport, ip->protocol, allowed ? 1 : 0);

	if (!allowed && !audit_mode)
		return TC_ACT_SHOT;
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
