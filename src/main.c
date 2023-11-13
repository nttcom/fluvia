/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/*
 * Copyright (c) 2023 NTT Communications Corporation
 * Copyright (c) 2023 Takeru Hayasaka
 */

#include "xdp_consts.h"
#include "xdp_struct.h"
#define KBUILD_MODNAME "xdp_probe"
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/seg6.h>
#include <linux/ioam6.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_map.h"

static inline int parse_ioam6_trace_header(struct ioam6_trace_hdr *ith, int hdr_len, struct metadata *key, void *data_end)
{
    __u8 second_index, subsecond_index;
    __u32 second, subsecond;

    if ((void *)(ith + 1) > data_end)
        return -1;

    second_index = hdr_len - 8;
    subsecond_index = hdr_len - 4;

    if ((void *)ith + second_index + 4 > data_end) return -1;
    second = bpf_ntohl(*(__u32 *)((void *)ith + second_index));

    if ((void *)ith + subsecond_index + 4 > data_end) return -1;
    subsecond = bpf_ntohl(*(__u32 *)((void *)ith + subsecond_index));

    key->sent_second = second;
    key->sent_subsecond = subsecond;

    return 0;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 packet_size = data_end - data;
    __u8 *p;
    struct metadata md = {};
    int ret, hoplen;

    struct ethhdr *eth = data;
    struct ipv6hdr *ipv6;
    struct srhhdr *srh;
    struct ipv6_hopopt_hdr *hopopth;
    struct ioam6_hdr *ioam6h;
    struct ioam6_trace_hdr *ioam6_trace_h;

    md.received_nanosecond = bpf_ktime_get_ns();

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    ipv6 = (void *)(eth + 1);
    if ((void *)(ipv6 + 1) > data_end)
        return XDP_PASS;

    if (ipv6->nexthdr != IPPROTO_HOPOPTS)
        return XDP_PASS;

    hopopth = (struct ipv6_hopopt_hdr *)(ipv6 + 1);
    if ((void *)(hopopth + 1) > data_end)
        return XDP_PASS;

    hoplen = (hopopth->hdrlen + 1) << 3;

    p = (__u8 *)(hopopth + 1);

    if ((void *)(p + 1) > data_end)
        return XDP_PASS;

    if (*p == IPV6_TLV_PAD1) {
        p += 1;
    }

    if ((void *)(p + 1) > data_end)
        return XDP_PASS;

    if (*p == IPV6_TLV_PAD1) {
        p += 1;
    }

    ioam6h = (struct ioam6_hdr *)p;
    if ((void *)(ioam6h + 1) > data_end) {
        return XDP_PASS;
    }

    if (ioam6h->opt_type != IPV6_TLV_IOAM) {
        return XDP_PASS;
    }

    if (ioam6h->type != IOAM6_TYPE_PREALLOC) {
        return XDP_PASS;
    }

    ioam6_trace_h = (struct ioam6_trace_hdr *)(ioam6h + 1);
    if ((void *)(ioam6_trace_h + 1) > data_end) {
        return XDP_PASS;
    }

    ret = parse_ioam6_trace_header(ioam6_trace_h, ioam6h->opt_len - 2, &md, data_end);
    if (ret != 0) {
        return XDP_PASS;
    }

    if (hopopth->nexthdr != IPPROTO_IPV6ROUTE)
        return XDP_PASS;

    srh = (struct srhhdr *)((void *)hopopth + hoplen);
    if ((void *)(srh + 1) > data_end)
        return XDP_PASS;

    if (srh->routingType != IPV6_SRCRT_TYPE_4) // IPV6_SRCRT_TYPE_4 = SRH
        return -1;

    __u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
    bpf_perf_event_output(ctx, &packet_probe_perf, flags, &md, sizeof(md));

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual MIT/GPL";
