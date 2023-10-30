/*
 * Copyright (c) 2023 NTT Communications Corporation
 * Copyright (c) 2023 Takeru Hayasaka
 */

#ifndef __XDP_MAPS_H
#define __XDP_MAPS_H
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_consts.h"
#include "xdp_struct.h"
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, MAX_MAP_ENTRIES);
} ipfix_probe_map SEC(".maps");

#endif
