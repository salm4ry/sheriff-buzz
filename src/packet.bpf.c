#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <asm/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "include/packet.h"
#include "include/patch_header.h"

char LICENSE[] SEC("license") = "GPL";

/* array of flagged IP addresses from which to block/redirect traffic */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); /* length of IPv4 address */
	__type(value, __u8);
	__uint(max_entries, 256);
} flagged_ips SEC(".maps");

/* config (sent from user space */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct config_rb_event);
	__uint(max_entries, 1); /* only one entry required: the current config */
} config SEC(".maps");

/* kernel ring buffer
 *
 * send TCP headers from kernel -> user space
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} xdp_rb SEC(".maps");

/* user ring buffer
 *
 * send IPs to block/redirect from user -> kernel space
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} flagged_rb SEC(".maps");

/* config options
 *
 * sent from user space
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} config_rb SEC(".maps");


/**
 * User ring buffer callback
 *
 * Add flagged IP sent from user space to BPF array map
 *
 * In general:
 * return 0: continue to try and drain next sample
 * return 1: skip the rest of the samples and return
 * other: not used- rejected by verifier
 */
static long flagged_rb_callback(struct bpf_dynptr *dynptr, void *ctx)
{
	/* bpf_map__update_elem(&flagged_ips,  */
	struct flagged_rb_event *sample;
	__u8 data = 1;

	sample = bpf_dynptr_data(dynptr, 0, sizeof(*sample));
	if (!sample) {
		return 0;
	}

	/* insert hash map entry for new flagged IP */
	bpf_map_update_elem(&flagged_ips, &sample->src_ip, &data, 0);
	return 0;
}

static long config_rb_callback(struct bpf_dynptr *dynptr, void *ctx)
{
	struct config_rb_event *sample = NULL;
	__u32 index = 0; /* only one element in config map (index 0) */

	sample = bpf_dynptr_data(dynptr, 0, sizeof(*sample));
	if (!sample) {
		return 0;
	}

	/* update config map entry */
	/* bpf_printk("updating config"); */
	bpf_map_update_elem(&config, &index, sample, 0);
	return 0;
}

SEC("uretprobe")
int read_flagged_rb()
{
	bpf_user_ringbuf_drain(&flagged_rb, flagged_rb_callback, NULL, 0);
	return 0;
}

SEC("uretprobe")
int read_config_rb()
{
	/* bpf_printk("reading config"); */
	bpf_user_ringbuf_drain(&config_rb, config_rb_callback, NULL, 0);
	return 0;
}


/* TODO second uretprobe and user ring buffer callback for config */

SEC("xdp")
int process_packet(struct xdp_md *ctx)
{
	__u8 protocol_number;
	/* __u64 *packet_entry; */
	__u32 src_ip;

	struct xdp_rb_event *e;

	__u32 config_index = 0; /* index 0 */
	struct config_rb_event *current_config;

	int result = XDP_PASS;  /* pass packet on to network stack */

	protocol_number = lookup_protocol(ctx);

	struct iphdr *ip_headers = parse_ip_headers(ctx);
	if (!ip_headers)
		return result;

	src_ip = src_addr(ip_headers);

	/* get config */
	current_config = bpf_map_lookup_elem(&config, &config_index);

	if (bpf_map_lookup_elem(&flagged_ips, &src_ip)) {
		/* lookup returns non-null => IP is flagged */
		/* TODO option to redirect instead of block */

		/* NOTE: commented out for soft blocking */
		/* result = XDP_DROP; */

		/* if we have config loaded */
		if (current_config) {
			if (current_config->block_src) {
				/* bpf_printk("action = block"); */
				/*
				result = XDP_DROP;
				*/
			} else {
				/* bpf_printk("action = redirect"); */
				/*
				change_dst_addr(ip_headers, current_config->redirect_ip);
				result = XDP_TX;
				*/
			}
		} else {
			/* otherwise block by default */
			/* result = XDP_DROP; */
		}

	/*
	} else if (src_ip == ntohl((__u32) 1128442048)) {
		// NOTE: testing redirection from 192.168.66.67 -> 192.168.66.254
		bpf_printk("changing destination address");
		change_dst_addr(ip_headers, 4265781440);
	*/

		/* XDP_TX = send packet back from the same interface it came from */
		/* result = XDP_TX; */
	} else {
		struct tcphdr *tcp_headers = parse_tcp_headers(ctx);
		if (!tcp_headers)
			return result;

		if (protocol_number == TCP_PNUM) {
			/* reserve ring buffer sample */
			e = bpf_ringbuf_reserve(&xdp_rb, sizeof(*e), 0);
			if (!e) {
				/* BPF ring buffer allocation failed */
				return result;
			}

			/* fill out ring buffer sample */
			e->ip_header = *ip_headers;
			e->tcp_header = *tcp_headers;

			/* submit ring buffer event */
			bpf_ringbuf_submit(e, 0);
		}
	}

	return result;
}
