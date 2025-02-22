#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <asm/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "include/bpf_common.h"
#include "include/patch_header.h"

/* TODO #define all map maximum sizes */
#define MAX_SUBNET 256
#define _XDP_STATE_UNKNOWN -1

/* TODO docstrings */

char LICENSE[] SEC("license") = "GPL";

struct bpf_subnet {
    in_addr_t network_addr;
    in_addr_t mask;
    __u16 type;
};

struct subnet_loop_ctx {
    in_addr_t src_ip;
    int type; /* blacklist/whitelist/not found */
};

/* hash map of black/whitelisted IPs */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); /* length of IPv4 address */
	__type(value, __u16);
	__uint(max_entries, 256);
} ip_list SEC(".maps");

/* array of black/whitelisted subnets */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct bpf_subnet);
	__uint(max_entries, MAX_SUBNET);
} subnet_list SEC(".maps");

/* hash map of whitelisted ports */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, __u16);
	__uint(max_entries, 256);
} port_list SEC(".maps");

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
	__uint(max_entries, (8 * 1024) * 1024); /* 8 MB */
} xdp_rb SEC(".maps");

/* IP user ring buffer
 *
 * send black/whitelisted IPs from user -> kernel space
 *
 * NOTE: IPs take precedence over subnets e.g. an IP being whitelisted takes
 * precedence over its subnet being blacklisted
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} ip_rb SEC(".maps");

/* subnet user ring buffer
 *
 * send black/whitelisted subnets from user -> kernel space
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} subnet_rb SEC(".maps");

/* port user ring buffer
 *
 * send whitelisted ports from user -> kernel space
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB  */
} port_rb SEC(".maps");

/* action config user ring buffer
 *
 * sent from user space
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} config_rb SEC(".maps");


#ifdef DEBUG
	#define bpf_debug(fmt, ...)  \
	bpf_printk(fmt, ##__VA_ARGS__);
#else
	#define bpf_debug(fmt, ...) \
		;
#endif


/**
 * IP user ring buffer callback
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

	bpf_debug("submitting ip %ld, blacklist = %d", sample->src_ip,
			sample->type == BLACKLIST);

	/* insert hash map entry for new black/whitelisted IP */
	bpf_map_update_elem(&ip_list, &sample->src_ip, &sample->type, 0);
	return 0;
}

static long subnet_rb_callback(struct bpf_dynptr *dynptr, void *ctx)
{
    struct subnet_rb_event *sample;
    struct bpf_subnet subnet;

    sample = bpf_dynptr_data(dynptr, 0, sizeof(*sample));
    if (!sample) {
        return 0;
    }

    bpf_debug("subnet index %d, blacklist = %d", sample->index,
            sample->type == BLACKLIST);

    /* insert array entry (using provided index) for new black/whitelisted
     * subnet */
    subnet.network_addr = sample->network_addr;
    subnet.mask = sample->mask;
    subnet.type = sample->type;
    bpf_map_update_elem(&subnet_list, &sample->index, &subnet, 0);
    return 0;
}

static long port_rb_callback(struct bpf_dynptr *dynptr, void *ctx)
{
	struct port_rb_event *sample;
	int type = WHITELIST;

	sample = bpf_dynptr_data(dynptr, 0, sizeof(*sample));
	if (!sample) {
		return 0;
	}

	bpf_debug("whitelist port %d", sample->port_num);

	/* insert hash map entry for new whitelisted port */
	bpf_map_update_elem(&port_list, &sample->port_num, &type, 0);

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
	bpf_debug("updating block/redirect config");
	bpf_map_update_elem(&config, &index, sample, 0);
	return 0;
}

/**
 * bpf_loop() callback for subnet array iteration: check whether the source IP
 * belongs to the subnet with the given index.
 *
 * index: current loop index (starting from 0)
 * ctx: source IP to check subnet for
 *
 * return:
 * 0: helper continues to next loop
 * 1: helper skips rest of the loops and returns
 */
static long subnet_loop_callback(__u64 index, void *ctx)
{
    struct bpf_subnet *subnet;
    struct subnet_loop_ctx *loop_ctx = ctx;

    subnet = bpf_map_lookup_elem(&subnet_list, &index);
    if (subnet) {
        if (in_subnet(loop_ctx->src_ip, subnet->network_addr, subnet->mask)) {
            switch (subnet->type) {
                case BLACKLIST:
                    /* set type to blacklist */
                    loop_ctx->type = BLACKLIST;
                    break;
                case WHITELIST:
                    /* set type to whitelist */
                    loop_ctx->type = WHITELIST;
                    break;
            }

            /* break out of bpf_loop() */
            return 1;
        } else {
            /* IP does not belong to this subnet- continue iterating with
             * bpf_loop() */
            return 0;
        }
    } else {
        /* reached the end of the list- break out of bpf_loop() */
        return 1;
    }
}

int handle_blacklist(__u32 src_ip, struct iphdr *ip_headers,
		struct config_rb_event *current_config)
{
	/* block by default */
	int packet_action = XDP_DROP;

	if (current_config) {
		if (current_config->block_src) {
			bpf_debug("block %lu", src_ip);

			if (!current_config->dry_run) {
				packet_action = XDP_DROP;
			}
		} else {
			/* NOTE: ip_headers NULL check required to pass verifier checks */
			if (ip_headers) {
				bpf_debug("redirect %lu to %lu", src_ip, current_config->redirect_ip);

				/* don't alter packet headers when in dry run mode */
				if (!current_config->dry_run) {
					change_dst_addr(ip_headers, current_config->redirect_ip);
					packet_action = XDP_TX;
				}
			}
		}
	}

	return packet_action;
}

int src_ip_state(__u32 src_ip, struct iphdr *ip_headers,
		struct config_rb_event *current_config)
{
	__u16 *ip_list_type;
	int packet_action = _XDP_STATE_UNKNOWN;

	/* look up source IP */
	ip_list_type = bpf_map_lookup_elem(&ip_list, &src_ip);

	if (ip_list_type) {
		switch (*ip_list_type) {
			case BLACKLIST:
				bpf_debug("IP lookup: %ld blacklisted", src_ip);
				packet_action = handle_blacklist(src_ip, ip_headers, current_config);
				break;
			default:
				bpf_debug("IP lookup: %ld whitelisted", src_ip);
				packet_action = XDP_PASS;
				break;
		}
	}

	return packet_action;
}

int subnet_state(__u32 src_ip)
{
	/* set up loop callback args */
	struct subnet_loop_ctx ctx = {
		.src_ip = src_ip,
		.type = -1
	};

	bpf_loop(MAX_SUBNET, &subnet_loop_callback, &ctx, 0);
	return ctx.type;
}

int dst_port_state(__u16 dst_port)
{
	/* translate to host byte order */
	__u16 key = bpf_ntohs(dst_port);
	__u16 *port_type = bpf_map_lookup_elem(&port_list, &key);
	int state = _XDP_STATE_UNKNOWN;

	if (port_type) {
		state = *port_type;
	}

	return state;
}

void submit_headers(struct iphdr *ip_headers, struct tcphdr *tcp_headers)
{
	struct xdp_rb_event *e;

	if (ip_headers && tcp_headers) {
	/* IP not black/whitelisted- send TCP headers to user space */

	/* reserve ring buffer sample */
	e = bpf_ringbuf_reserve(&xdp_rb, sizeof(*e), 0);
	if (!e) {
		bpf_debug("XDP ring buffer allocation failed");
		return;
	}

	/* fill out ring buffer sample */
	e->ip_header = *ip_headers;
	e->tcp_header = *tcp_headers;

	/* submit ring buffer event */
	bpf_ringbuf_submit(e, 0);
	}
}

SEC("uretprobe")
int read_ip_rb()
{
	bpf_user_ringbuf_drain(&ip_rb, ip_rb_callback, NULL, 0);
	return 0;
}

SEC("uretprobe")
int read_subnet_rb()
{
    bpf_user_ringbuf_drain(&subnet_rb, subnet_rb_callback, NULL, 0);
    return 0;
}

SEC("uretprobe")
int read_port_rb()
{
	bpf_user_ringbuf_drain(&port_rb, port_rb_callback, NULL, 0);
	return 0;
}

SEC("uretprobe")
int read_config_rb()
{
	bpf_user_ringbuf_drain(&config_rb, config_rb_callback, NULL, 0);
	return 0;
}

SEC("xdp")
int process_packet(struct xdp_md *ctx)
{
	__u8 protocol_number;
	__u32 src_ip;

	int packet_action = XDP_PASS;
	int subnet_type;

	const __u32 CONFIG_INDEX = 0; /* index 0 */

	protocol_number = lookup_protocol(ctx);

	struct iphdr *ip_headers = parse_ip_headers(ctx);
	if (!ip_headers) {
		return packet_action;
	}

	struct config_rb_event *current_config = bpf_map_lookup_elem(&config, &CONFIG_INDEX);

	src_ip = src_addr(ip_headers);

	/*
	switch (protocol_number) {
		case ICMP_PNUM:
			bpf_debug("ICMP from %ld", src_ip);
			break;
		case TCP_PNUM:
			bpf_debug("TCP from %ld", src_ip);
			break;
	}
	*/

	packet_action = src_ip_state(src_ip, ip_headers, current_config);
	if (packet_action != _XDP_STATE_UNKNOWN) {
		/* block/redirect without checking subnet */
		bpf_debug("return after IP lookup: pass = %d, drop = %d, tx  = %d",
				packet_action == XDP_PASS, packet_action == XDP_DROP, packet_action == XDP_TX);
	} else {
		/* reset back to passing */
		packet_action = XDP_PASS;

		/* does the IP belong to blacklisted/whitelisted subnet? */
		subnet_type = subnet_state(src_ip);
		switch (subnet_type) {
			case BLACKLIST:
				bpf_debug("%ld belongs to blacklisted subnet", src_ip);
				packet_action = handle_blacklist(src_ip, ip_headers, current_config);
				bpf_debug("subnet lookup result: drop = %d, tx = %d",
						packet_action == XDP_DROP, packet_action == XDP_TX);
				break;
			case WHITELIST:
				/* whitelisted: pass packet on */
				bpf_debug("%ld belongs to whitelisted subnet", src_ip);
				break;
			default:
				/* submit IP & TCP headers to ring buffer for user space
				 * processing (if applicable) */
				if (protocol_number == TCP_PNUM) {
					struct tcphdr *tcp_headers = parse_tcp_headers(ctx);
					/* check whether port is whitelisted */
					if (tcp_headers) {
						if (dst_port_state(tcp_headers->dest) == WHITELIST) {
							bpf_debug("port %d whitelisted", bpf_ntohs(tcp_headers->dest));
						} else {
							submit_headers(ip_headers, tcp_headers);
						}
			    	}
				}
				break;
		}
	}

	/* reset to XDP_PASS before returning */
	if (current_config) {
		if (current_config->dry_run) {
			packet_action = XDP_PASS;
		}
	}
	bpf_debug("%ld, pass = %d drop = %d, tx  = %d",
			src_ip, packet_action == XDP_PASS, packet_action == XDP_DROP, packet_action == XDP_TX);
	return packet_action;
}
