// Minimal types for compiling censor.c without full vmlinux.
#pragma once

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;

#define __section(NAME) __attribute__((section(NAME), used))
#ifndef SEC
#define SEC(NAME) __section(NAME)
#endif

struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
};

struct iphdr {
	__u8 ihl:4;
	__u8 version:4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__u32 u6_addr32[4];
	} in6_u;
};

struct ipv6hdr {
	__u8 priority:4;
	__u8 version:4;
	__u8 flow_lbl[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
};

struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 msg_src_ip4;
	__u32 msg_src_ip6[4];
	__u32 __pad;
};
