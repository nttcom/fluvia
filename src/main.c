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
    __u8 *data;
    __u64 epoch_time, boot_time;
    __u32 packet_tstamp, second, subsecond;

    data = ith->data + ith->remlen * 4 - ith->nodelen * 4;

    // timestamp seconds
    if (ith->type.bit2) {
        packet_tstamp = bpf_ntohl(*(__be32 *)data);

        key->tstamp_second = packet_tstamp;

        boot_time = bpf_ktime_get_ns();
        // TODO
        // Pass diff = epoch_time - boot_time from user space via map,
        // then calculate epoch_time by adding boot_time and diff
        epoch_time = boot_time; // + diff

        second = epoch_time / 1000000000;
        *(__be32 *)data = bpf_htonl(second);

        data += sizeof(__be32);
    }

    if (ith->type.bit3) {
        packet_tstamp = bpf_ntohl(*(__be32 *)data);

        key->tstamp_subsecond = packet_tstamp;

        boot_time = bpf_ktime_get_ns();
        // TODO
        // Pass diff = epoch_time - boot_time from user space via map,
        // then calculate epoch_time by adding boot_time and diff
        epoch_time = boot_time; // + diff

        subsecond = epoch_time % 1000000000;
        *(__be32 *)data = bpf_htonl(subsecond);

        data += sizeof(__be32);
    }

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
    __u8 nh;
    int ret, hoplen;

    struct ethhdr *eth = data;
    struct ipv6hdr *ipv6;
    struct srhhdr *srh;
    struct ipv6_hopopt_hdr *hopopth;
    struct ioam6_hdr *ioam6h;
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

    p = (void *)(ipv6 + 1);
    nh = ipv6->nexthdr;
    for (int i = 0; i < MAX_PROCESSED_EXTHDR; i++) {
        if (nh == IPPROTO_IPV6ROUTE) {
            srh = (struct srhhdr *)p;

            if ((void *)(srh + 1) > data_end)
                return XDP_PASS;

            ret = parse_srv6(srh, &key, data_end);
            if (ret != 0)
                bpf_printk("fail to parse_srv6 fail");
                return XDP_PASS;

            nh = srh->nextHdr;
            p = (void *)(srh + 1) + srh->hdrExtLen * 8 - 16;
        } else if (nh == IPPROTO_HOPOPTS) {
            hopopth = (struct ipv6_hopopt_hdr *)p;
            nh = hopopth->nexthdr;
            hoplen = (hopopth->hdrlen + 1) << 3;

            p += sizeof(struct ipv6_hopopt_hdr);

            while (hoplen > 0) {
                // If not IPV6_TLV_IOAM
                if (p[0] != IPV6_TLV_IOAM) {
                    p += p[1] + 2;
                    hoplen -= p[1] + 2;
                    continue;
                }

                ioam6h = (struct ioam6_hdr *)p;
                if (ioam6h->type == IOAM6_TYPE_PREALLOC) {
                    p += sizeof(*ioam6h);
                    ret = parse_ioam6_trace_header((struct ioam6_trace_hdr *)p, &key, data_end);
                    if (ret != 0) {
                        bpf_printk("failed to parse ioam6 trace header");
                        return XDP_PASS;
                    }
                }

                p += ioam6h->opt_len + 2;
                hoplen -= ioam6h->opt_len + 2;
            }
        }
    }

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
