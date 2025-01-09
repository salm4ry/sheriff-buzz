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
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); /* length of IPv4 address */
	__type(value, __u8);
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

/*
 * User ring buffer callback
 *
 * Add flagged IP sent from user space to BPF array map
 *
 * In general:
 * return 0: continue to try and drain next sample
 * return 1: skip the rest of the samples and return
 * other: not used- rejected by verifier
 */
static long user_rb_callback(const struct bpf_dynptr *dynptr, void *ctx)
{
	/* bpf_map__update_elem(&flagged_ips,  */
	struct user_rb_event *sample;
	__u8 data = 1;

	sample = bpf_dynptr_data(dynptr, 0, sizeof(*sample));
	if (!sample) {
		return 0;
	}

	/* insert array entry */
	bpf_map_update_elem(&flagged_ips, &sample->src_ip, &data, 0);
	return 0;
}

SEC("uretprobe")
int read_user_ringbuf()
{
	bpf_user_ringbuf_drain(&user_rb, &user_rb_callback, NULL, 0);
	return 0;
}

SEC("xdp")
int process_packet(struct xdp_md *ctx)
{
	__u8 protocol_number;
	/* __u64 *packet_entry; */
	__u32 src_addr;

	struct kernel_rb_event *e;

	int result = XDP_PASS;  /* pass packet on to network stack */

	protocol_number = lookup_protocol(ctx);

	struct iphdr *ip_headers = get_ip_headers(ctx);
	if (!ip_headers)
		return result;

	struct tcphdr *tcp_headers = get_tcp_headers(ctx);
	if (!tcp_headers)
		return result;

	if (protocol_number == TCP_PNUM) {
		src_addr = get_source_addr(ip_headers);
		__u8 *lookup_res = bpf_map_lookup_elem(&flagged_ips, &src_addr);

		/* lookup returns non-null => IP is flagged */
		if (lookup_res != NULL) {
			/* TODO redirect */
			/* drop for now */
			result = XDP_DROP;
		} else {
			/* reserve ring buffer sample */
			e = bpf_ringbuf_reserve(&kernel_rb, sizeof(*e), 0);
			if (!e) {
				/* BPF ring buffer allocation failed */
				return result;
			}

			/* fill out ring buffer sample */
			e->iph = *ip_headers;
			e->tcph = *tcp_headers;

			/* submit ring buffer event */
			bpf_ringbuf_submit(e, 0);
		}
	}

	return result;
}
