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

/* TODO #define all map maximum sizes */
#define MAX_SUBNET 256

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

	bpf_debug("ip %ld, blacklist = %d", sample->src_ip,
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
int read_config_rb()
{
	bpf_user_ringbuf_drain(&config_rb, config_rb_callback, NULL, 0);
	return 0;
}

SEC("xdp")
int process_packet(struct xdp_md *ctx)
{
	__u8 protocol_number;
	__u16 *ip_list_type;
	__u32 src_ip;

    struct subnet_loop_ctx loop_ctx;

	int result = XDP_PASS;

	struct xdp_rb_event *e;

	const __u32 CONFIG_INDEX = 0; /* index 0 */
	struct config_rb_event *current_config;

	protocol_number = lookup_protocol(ctx);

	struct iphdr *ip_headers = parse_ip_headers(ctx);
	if (!ip_headers)
		return result;

	src_ip = src_addr(ip_headers);

	/* NOTE: test if IP belongs to subnet 192.168.66.0/24
	__u32 example_network = 4368576;
	__u32 example_mask = 16777215;

	bpf_printk("IP %u belongs to subnet: %d",
			src_ip, in_subnet(src_ip, example_network, example_mask));
	*/

	/* look up source IP */
	ip_list_type = bpf_map_lookup_elem(&ip_list, &src_ip);
	if (ip_list_type) {
		bpf_debug("%lu -> blacklist = %d", src_ip, *ip_list_type == BLACKLIST);

		switch (*ip_list_type) {
			case BLACKLIST:
                /* look up config to check block/redirect action */
                current_config = bpf_map_lookup_elem(&config, &CONFIG_INDEX);

				/* check config for action */
				if (current_config) {
					/* block source IP */
					if (current_config->block_src) {
						bpf_debug("action for %lu = block", src_ip);
						/* NOTE "soft block"
						result = XDP_DROP;
						*/
					} else {
						bpf_debug("action for %lu = redirect", src_ip);

						/* XDP_TX = send packet back on the same interface it
						 * came from */
						/* NOTE "soft redirect"
						change_dst_addr(ip_headers, current_config->redirect_ip);
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
				bpf_debug("%ld whitelisted", src_ip);
				break;
		}
	}     /* look up subnet */

    /* set up arguments for loop callback function */
    loop_ctx.src_ip = src_ip;
    loop_ctx.type = -1;

    /* iterate through populated portion of subnet array */
    bpf_loop(MAX_SUBNET, &subnet_loop_callback, &loop_ctx, 0);

    switch (loop_ctx.type) {
        case BLACKLIST:
            /* blacklisted- block/redirect based on config action */
            current_config = bpf_map_lookup_elem(&config, &CONFIG_INDEX);
            if (current_config) {
                if (current_config->block_src) {
                    bpf_debug("action for %lu = block", src_ip);

                    /* NOTE "soft block"
                    result = XDP_DROP
                    */
                } else {
                    bpf_debug("action for %lu = redirect", src_ip);
                    /* XDP_TX = send packet back on the same interface it came
                     * from */

                    /* NOTE "soft redirect"
                    change_dst_addr(ip_headers, current_config->redirect_ip);
                    result = XDP_TX;
                    */
                }
            } else {
                /* block by default */
                /* NOTE "soft block"
                return XDP_DROP;
                */
            }
            break;
        case WHITELIST:
            /* whitelisted: pass packet on */
				bpf_debug("%ld belongs to whitelisted subnet", src_ip);
            return XDP_PASS;
        default:
            /* submit TCP headers to ring buffer for user space processing (if
             * applicable) */
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
