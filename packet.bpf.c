#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <asm/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "packet.h"

char LICENSE[] SEC("license") = "GPL";

/* array of flagged IP addresses from which to block/redirect traffic */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);  /* length of IPv4 address */
	__uint(max_entries, 256);
} flagged_ips SEC(".maps");

/* kernel ring buffer
 *
 * send TCP headers from kernel -> user space
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} kernel_rb SEC(".maps");

/* user ring buffer
 *
 * send IPs to block/redirect from user -> kernel space
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024);
} user_rb SEC(".maps");


SEC("xdp")
int process_packet(struct xdp_md *ctx)
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
		/* reserve ring buffer sample */
		e = bpf_ringbuf_reserve(&kernel_rb, sizeof(*e), 0);
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
