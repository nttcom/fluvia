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

static inline int parse_srv6(struct srhhdr *srh, struct probe_data *key, void *data_end)
{
    if ((void *)(srh + 1) > data_end) {
        return -1;
    }
    if (srh->routingType != IPV6_SRCRT_TYPE_4) // IPV6_SRCRT_TYPE_4 = SRH
        return -1;

    key->nextHdr = srh->nextHdr;
    key->hdrExtLen = srh->hdrExtLen;
    key->routingType = srh->routingType;
    key->segmentsLeft = srh->segmentsLeft;
    key->lastEntry = srh->lastEntry;
    key->flags = srh->flags;
    key->tag = srh->tag;

    for (int i = 0; i < MAX_SEGMENTLIST_ENTRIES; i++)
    {
        if (!(i < key->lastEntry + 1))
            break;

        if ((void *)(srh + sizeof(struct srhhdr) + sizeof(struct in6_addr) * (i + 1) + 1) > data_end)
            break;

        __builtin_memcpy(&key->segments[i], &srh->segments[i], sizeof(struct in6_addr));
    }

    return 0;
}

static inline int parse_ioam6_trace_header(struct ioam6_trace_hdr *ith, struct probe_data *key, void *data_end)
{
    int nodelen, second_index, subsecond_index;
    __u32 second, subsecond;

    nodelen = ith->nodelen << 2;
    second_index = nodelen - 8;
    subsecond_index = nodelen - 4;

    if ((void *)(ith->data + nodelen) > data_end)
        return XDP_PASS;

    second = *(__u32 *)(ith->data + second_index);
    subsecond = *(__u32 *)(ith->data + subsecond_index);

    key->tstamp_second = second;
    key->tstamp_subsecond = subsecond;

    return 0;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u8 *p;
    __u32 probe_key = XDP_PASS;
    struct probe_data key = {};
    __u64 zero = 0, *value;
    int ret, hoplen;

    struct ethhdr *eth = data;
    struct ipv6hdr *ipv6;
    struct srhhdr *srh;
    struct ipv6_hopopt_hdr *hopopth;
    struct ioam6_hdr *ioam6h;
    __u8 ioam6_opt_type;
    struct ioam6_trace_hdr *ioam6_trace_h;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    key.h_proto = eth->h_proto;
    __builtin_memcpy(&key.h_source, &eth->h_source, ETH_ALEN);
    __builtin_memcpy(&key.h_dest, &eth->h_dest, ETH_ALEN);

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    ipv6 = (void *)(eth + 1);
    if ((void *)(ipv6 + 1) > data_end)
        return XDP_PASS;

    key.v6_srcaddr = ipv6->saddr;
    key.v6_dstaddr = ipv6->daddr;

    if (ipv6->nexthdr != IPPROTO_HOPOPTS)
        return XDP_PASS;

    hopopth = (struct ipv6_hopopt_hdr *)(ipv6 + 1);
    if ((void *)(hopopth + 1) > data_end)
        return XDP_PASS;

    hoplen = (hopopth->hdrlen + 1) << 3;

    ioam6h = (struct ioam6_hdr *)(hopopth + 1);
    if ((void *)(ioam6h + 1) > data_end)
        return XDP_PASS;

    if (ioam6h->opt_type != IPV6_TLV_IOAM)
        return XDP_PASS;

    if (ioam6h->type != IOAM6_TYPE_PREALLOC)
        return XDP_PASS;

    ioam6_trace_h = (struct ioam6_trace_hdr *)(ioam6h + 1);
    if ((void *)(ioam6_trace_h + 1) > data_end)
        return XDP_PASS;

    ret = parse_ioam6_trace_header(ioam6_trace_h, &key, data_end);
    if (ret != 0) {
        bpf_printk("failed to parse ioam6 trace header");
        return XDP_PASS;
    }

    if (hopopth->nexthdr != IPPROTO_IPV6ROUTE)
        return XDP_PASS;

    srh = (struct srhhdr *)((void *)hopopth + hoplen);
    if ((void *)(srh + 1) > data_end)
        return XDP_PASS;

    ret = parse_srv6(srh, &key, data_end);
    if (ret != 0)
        bpf_printk("fail to parse_srv6 fail");
        return XDP_PASS;

    value = bpf_map_lookup_elem(&ipfix_probe_map, &key);
    if (!value)
    {
        bpf_map_update_elem(&ipfix_probe_map, &key, &zero, BPF_NOEXIST);
        value = bpf_map_lookup_elem(&ipfix_probe_map, &key);
        if (!value)
            return XDP_PASS;
    }
    (*value)++;

    return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
