// SPDX-License-Identifier: GPL-2.0
/*
 * XDP Flow Feature Extraction Probe — Layer 1 High-Throughput Ingress Telemetry.
 *
 * Extracts the 5-tuple, packet timing, payload/header lengths, TCP flags, and
 * window size directly at the NIC driver level (XDP hook) and submits compact
 * binary packet events to userspace via a BPF ring buffer.
 *
 * Safety Invariant:
 *   This program is strictly PASSIVE. It ALWAYS returns XDP_PASS.
 *   It NEVER alters, redirects, or drops packets.
 *   Mitigation actions remain exclusively governed by PendingActionManager.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

/*
 * Compact binary representation of parsed packet metadata emitted to userspace.
 * Packed to ensure zero padding and exact struct layout parity with Python ctypes.
 */
struct packet_event {
    __u64 timestamp_ns;  /* Kernel monotonic timestamp in nanoseconds */
    __u32 src_ip;        /* Source IPv4 address in network byte order */
    __u32 dst_ip;        /* Destination IPv4 address in network byte order */
    __u16 src_port;      /* Source transport port (host byte order) */
    __u16 dst_port;      /* Destination transport port (host byte order) */
    __u8  protocol;      /* IP protocol (IPPROTO_TCP, IPPROTO_UDP, etc.) */
    __u8  tcp_flags;     /* Bitmask of TCP flags (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR) */
    __u16 payload_len;   /* Transport-layer payload size in bytes */
    __u16 header_len;    /* Combined L3 + L4 header length in bytes */
    __u16 tcp_window;    /* TCP advertised receive window size */
} __attribute__((packed));

/*
 * BPF Ring Buffer for low-overhead kernel-to-userspace event streaming.
 * Ring buffer provides memory-mapped circular buffer with multi-producer,
 * single-consumer lockless ring semantics.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB ring buffer */
} packet_ringbuf SEC(".maps");

/*
 * Per-CPU array map tracking ring buffer drop events caused by buffer exhaustion
 * (backpressure from userspace).
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_drops SEC(".maps");

SEC("xdp")
int xdp_probe(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Parse Ethernet Header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic for DDoS flow feature extraction */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 2. Parse IPv4 Header */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 ip_hl = ip->ihl * 4;
    if (ip_hl < sizeof(*ip) || (void *)ip + ip_hl > data_end)
        return XDP_PASS;

    __u16 tot_len = bpf_ntohs(ip->tot_len);
    if (tot_len < ip_hl)
        return XDP_PASS;

    __u8 proto = ip->protocol;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8 tcp_flags = 0;
    __u16 tcp_window = 0;
    __u16 l4_hl = 0;
    __u16 payload_len = 0;

    void *l4_hdr = (void *)ip + ip_hl;

    /* 3. Parse Transport Layer */
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        l4_hl = tcp->doff * 4;
        if (l4_hl < sizeof(*tcp) || (void *)tcp + l4_hl > data_end)
            return XDP_PASS;

        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
        tcp_window = bpf_ntohs(tcp->window);

        /* Construct 8-bit TCP flag bitmask:
         * bit 0: FIN, bit 1: SYN, bit 2: RST, bit 3: PSH,
         * bit 4: ACK, bit 5: URG, bit 6: ECE, bit 7: CWR
         */
        tcp_flags = (tcp->fin ? 0x01 : 0) |
                    (tcp->syn ? 0x02 : 0) |
                    (tcp->rst ? 0x04 : 0) |
                    (tcp->psh ? 0x08 : 0) |
                    (tcp->ack ? 0x10 : 0) |
                    (tcp->urg ? 0x20 : 0) |
                    (tcp->ece ? 0x40 : 0) |
                    (tcp->cwr ? 0x80 : 0);

        if (tot_len >= ip_hl + l4_hl)
            payload_len = tot_len - (ip_hl + l4_hl);

    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        l4_hl = sizeof(*udp);
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);

        __u16 udp_len = bpf_ntohs(udp->len);
        if (udp_len >= sizeof(*udp))
            payload_len = udp_len - sizeof(*udp);
    } else {
        /* Other protocols (e.g. ICMP): transport ports remain 0 */
        l4_hl = 0;
        if (tot_len >= ip_hl)
            payload_len = tot_len - ip_hl;
    }

    /* 4. Reserve Ring Buffer Space with Backpressure Accounting */
    struct packet_event *event = bpf_ringbuf_reserve(&packet_ringbuf, sizeof(*event), 0);
    if (!event) {
        /* Ring buffer full: track drop counter and pass packet gracefully */
        __u32 key = 0;
        __u64 *drops = bpf_map_lookup_elem(&ringbuf_drops, &key);
        if (drops) {
            __sync_fetch_and_add(drops, 1);
        }
        return XDP_PASS;
    }

    /* 5. Populate and Submit Packet Event */
    event->timestamp_ns = bpf_ktime_get_ns();
    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->protocol = proto;
    event->tcp_flags = tcp_flags;
    event->payload_len = payload_len;
    event->header_len = ip_hl + l4_hl;
    event->tcp_window = tcp_window;

    bpf_ringbuf_submit(event, 0);

    /* Strictly PASS packet downstream to kernel network stack */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
