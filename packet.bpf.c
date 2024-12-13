#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <asm/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "packet.h"

/* key for packet hash map */
struct packet_key {
	__u32 protocol;
	__u32 src_ip;
};

/* value for packet hash map */
struct packet_value {
	__u64 count;
};

char LICENSE[] SEC("license") = "GPL";

/* TODO cut hash map down and do most of the packet counting/log processing in user
 * space */

/* hash map: protocol number -> packet count */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key, struct packet_key);
	__type(value, struct packet_value);
} protocol_counts SEC(".maps");

/* ring buffer */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} rb SEC(".maps");

SEC("xdp")
int hello_packet(struct xdp_md *ctx)
{
	struct packet_key current_key;
	struct packet_value current_value;
	__u64 *packet_entry;
	__u64 timestamp = bpf_ktime_get_ns();

	struct rb_event *e;

	int result = XDP_PASS;  /* pass packet on to network stack */

	current_key.protocol = lookup_protocol(ctx);

	struct iphdr *ip_headers = get_ip_headers(ctx);
	if (!ip_headers)
		return result;

	struct tcphdr *tcp_headers = get_tcp_headers(ctx);
	if (!tcp_headers)
		return result;

	if (current_key.protocol == TCP_PNUM) {
		/* update hash map key: protocol and source IP */
		current_key.src_ip = bpf_ntohl(ip_headers->saddr);

		/* initialise packet count (part of hash map value) */
		current_value.count = 0;

		/* update packet count */
		packet_entry = bpf_map_lookup_elem(&protocol_counts, &current_key);
		if (packet_entry) {
			/* set count if protocol number is valid */
			current_value.count = *packet_entry;
		}

		/* count current port */

		current_value.count++;

		bpf_map_update_elem(&protocol_counts, &current_key, &current_value, 0);

		/* reserve ring buffer sample */
		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
		if (!e) {
			/* BPF ring buffer allocation failed */
			return result;
		}

		/* fill out ring buffer sample */
		e->iph = *ip_headers;
		e->tcph = *tcp_headers;

		e->timestamp = timestamp;
		e->count = current_value.count;

		/* submit ring buffer event */
		bpf_ringbuf_submit(e, 0);

		/*
		e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

		if (!e)
			return result;

		e->count = current_value.count;
		e->src_ip = get_source_addr(ctx);
		e->dst_port = get_dst_port(ctx);

		e->flags[FIN] = get_tcp_flag(ctx, TCP_FLAG_FIN);
		e->flags[SYN] = get_tcp_flag(ctx, TCP_FLAG_SYN);
		e->flags[RST] = get_tcp_flag(ctx, TCP_FLAG_RST);
		e->flags[PSH] = get_tcp_flag(ctx, TCP_FLAG_PSH);
		e->flags[ACK] = get_tcp_flag(ctx, TCP_FLAG_ACK);
		e->flags[URG] = get_tcp_flag(ctx, TCP_FLAG_URG);
		e->flags[ECE] = get_tcp_flag(ctx, TCP_FLAG_ECE);
		e->flags[CWR] = get_tcp_flag(ctx, TCP_FLAG_CWR);

		bpf_ringbuf_submit(e, 0);
		*/
	}

	return result;
}
