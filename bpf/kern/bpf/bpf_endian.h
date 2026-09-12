#pragma once

#define __bpf_ntohs(x) __builtin_bswap16(x)
#define __bpf_htons(x) __builtin_bswap16(x)
#define bpf_htons(x) __bpf_htons(x)
#define bpf_ntohs(x) __bpf_ntohs(x)
