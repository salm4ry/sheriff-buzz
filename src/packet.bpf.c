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
	__type(value, __u16);
	__uint(max_entries, 256);
} ip_list SEC(".maps");

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
} ip_rb SEC(".maps");

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
 * Add black/whitelisted IP sent from user space to BPF array map
 *
 * In general:
 * return 0: continue to try and drain next sample
 * return 1: skip the rest of the samples and return
 * other: not used- rejected by verifier
 */
static long ip_rb_callback(struct bpf_dynptr *dynptr, void *ctx)
{
	/* bpf_map__update_elem(&flagged_ips,  */
	struct ip_rb_event *sample;

	sample = bpf_dynptr_data(dynptr, 0, sizeof(*sample));
	if (!sample) {
		return 0;
	}

	/* bpf_printk("received %ld, %d", sample->src_ip, sample->type); */

	/* insert hash map entry for new black/whitelisted IP */
	bpf_map_update_elem(&ip_list, &sample->src_ip, &sample->type, 0);
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
int read_ip_rb()
{
	bpf_user_ringbuf_drain(&ip_rb, ip_rb_callback, NULL, 0);
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
	__u16 *ip_list_type;
	__u32 src_ip;

	int result = XDP_PASS;

	struct xdp_rb_event *e;

	__u32 config_index = 0; /* index 0 */
	struct config_rb_event *current_config;

	protocol_number = lookup_protocol(ctx);

	struct iphdr *ip_headers = parse_ip_headers(ctx);
	if (!ip_headers)
		return result;

	src_ip = src_addr(ip_headers);

	/* get config */
	current_config = bpf_map_lookup_elem(&config, &config_index);

	/* look up source IP */
	ip_list_type = bpf_map_lookup_elem(&ip_list, &src_ip);

	if (ip_list_type) {
		/* bpf_printk("%lu -> %x", src_ip, *ip_list_type); */
		switch (*ip_list_type) {
			case BLACKLIST:
				/* check config for action */
				if (current_config) {
					/* block source IP */
					if (current_config->block_src) {
						bpf_printk("action = block");
						/* NOTE "soft block"
						result = XDP_DROP;
						*/
					} else {
						bpf_printk("action = redirect");
						change_dst_addr(ip_headers, current_config->redirect_ip);

						/* XDP_TX = send packet back on the same interface it
						 * came from */
						/* NOTE "soft redirect"
						result = XDP_TX;
						*/
					}
				} else {
					/* otherwise block by default */
					/* NOTE "soft block"
					return XDP_DROP;
					*/
				}
				break;
			default:
				/* whitelisted: pass packet on (result is already set to
				 * XDP_PASS) */
				/* bpf_printk("whitelisted"); */
				break;
		}
	} else {
		/* bpf_printk("%lu not found", src_ip); */
		if (protocol_number == TCP_PNUM) {
			/* IP not black/whitelisted- send TCP headers to user space */
			struct tcphdr *tcp_headers = parse_tcp_headers(ctx);
			if (!tcp_headers)
				return result;

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
