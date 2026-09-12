#pragma once
/* Minimal BPF helper declarations for compiling censor.c with clang -target bpf. */

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PROG_ARRAY 3
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_PERCPU_HASH 5
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_LPM_TRIE 11
#define BPF_MAP_TYPE_RINGBUF 27

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, unsigned long long flags) = (void *)2;
static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, unsigned long long buf_size) = (void *)16;
static unsigned long long (*bpf_get_socket_cookie)(void *ctx) = (void *)46;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, unsigned long long size, unsigned long long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *)132;

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
