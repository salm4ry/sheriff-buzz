#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <asm/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "packet.h"

/*
struct packet_key {
	__u32 protocol;
	__u32 src_ip;
};

struct packet_value {
	__u64 count;
};
*/

char LICENSE[] SEC("license") = "GPL";

/*
// hash map: protocol number -> packet count
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key, struct packet_key);
	__type(value, struct packet_value);
} protocol_counts SEC(".maps");
*/

/* ring buffer */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} rb SEC(".maps");

SEC("xdp")
int hello_packet(struct xdp_md *ctx)
{
	__u8 protocol_number;
	/* __u64 *packet_entry; */
	__u64 timestamp = bpf_ktime_get_ns();

	struct rb_event *e;

	int result = XDP_PASS;  /* pass packet on to network stack */

	protocol_number = lookup_protocol(ctx);

	struct iphdr *ip_headers = get_ip_headers(ctx);
	if (!ip_headers)
		return result;

	struct tcphdr *tcp_headers = get_tcp_headers(ctx);
	if (!tcp_headers)
		return result;

	if (protocol_number == TCP_PNUM) {
		/*
		// update hash map key: protocol and source IP
		current_key.src_ip = bpf_ntohl(ip_headers->saddr);

		// initialise packet count (part of hash map value)
		current_value.count = 0;

		// update packet count
		packet_entry = bpf_map_lookup_elem(&protocol_counts, &current_key);
		if (packet_entry) {
			// set count if protocol number is valid
			current_value.count = *packet_entry;
		}

		// count current port
		current_value.count++;

		bpf_map_update_elem(&protocol_counts, &current_key, &current_value, 0);
		*/

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

		/* submit ring buffer event */
		bpf_ringbuf_submit(e, 0);
	}

	return result;
}
