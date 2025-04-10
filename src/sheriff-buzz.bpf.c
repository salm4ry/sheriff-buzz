#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <asm/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "include/bpf_common.h"
#include "sys/cdefs.h"

/* TODO docstrings */

char LICENSE[] SEC("license") = "GPL";

struct bpf_subnet {
	in_addr_t network_addr;
	in_addr_t mask;
	short type;
};

struct subnet_loop_ctx {
	in_addr_t src_ip;
	short type; /* blacklist/whitelist/not found */
};

/* hash map of black/whitelisted IPs */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32); /* length of IPv4 address */
	__type(value, short);
	__uint(max_entries, 16384);
} ip_list SEC(".maps");

/* array of black/whitelisted subnets */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct bpf_subnet);
	__uint(max_entries, 128);
} subnet_list SEC(".maps");

/* hash map of whitelisted ports */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u16);
	__type(value, short);
	__uint(max_entries, 1024);
} port_list SEC(".maps");

/* config (sent from user space */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct config_rb_event);
	__uint(max_entries, 1); /* only one entry required: the current config */
} config SEC(".maps");

/* used for XDP unit testing */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, __u16);
	__uint(max_entries, 128);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} test_results SEC(".maps");

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

__u32 src_addr(struct iphdr *ip_header)
{
	return ip_header->saddr;
}

__always_inline __u8 lookup_protocol(struct xdp_md *ctx)
{
	__u8 protocol = 0;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = (struct ethhdr *) data;

	/* cast to char (= 1 byte) for correct pointer arithmetic */
	if ((char *) data + sizeof(struct ethhdr) > (char *) data_end)
		return 0;

	/* check that it's an IP packet */
	if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
		/* return the protocol of this packet
		 * 1 = ICMP, 6 = TCP, 17 = UDP */
		struct iphdr *iph = (struct iphdr *) ((char *) data + sizeof(struct ethhdr));
		if ((char *) data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= (char *) data_end)
			protocol = iph->protocol;
	}

	return protocol;
}

__always_inline struct iphdr *parse_ip_headers(struct xdp_md *ctx)
{
	struct ethhdr *eth_header = NULL;
	struct iphdr *ip_header = NULL;

	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	if ((char *) data + sizeof(struct ethhdr) + sizeof(struct iphdr)
			> (char *) data_end) {
		goto fail;
	}

	eth_header = (struct ethhdr *) data;

	if (bpf_ntohs(eth_header->h_proto) == ETH_P_IP) {
		ip_header = (struct iphdr *) ((char *) data + sizeof(struct ethhdr));
	}

fail:
	return ip_header;
}

__always_inline struct tcphdr *parse_tcp_headers(struct xdp_md *ctx)
{
	struct tcphdr *tcph = NULL;

	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	if ((char *) data + sizeof(struct ethhdr) + sizeof(struct iphdr)
			+ sizeof(struct tcphdr) > (char *) data_end)  {
		goto fail;
	}

	if (lookup_protocol(ctx) == TCP_PNUM) {
		tcph = (struct tcphdr *) ((char *) data + sizeof(struct ethhdr)
				+ sizeof(struct iphdr));
	}

fail:
	return tcph;
}

__always_inline struct udphdr *parse_udp_headers(struct xdp_md *ctx)
{
	struct udphdr *udph = NULL;

	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	if ((char *) data + sizeof(struct ethhdr) + sizeof(struct iphdr)
			+ sizeof(struct udphdr) > (char *) data_end) {
		goto fail;
	}

	if (lookup_protocol(ctx) == UDP_PNUM) {
		udph = (struct udphdr *) ((char *) data + sizeof(struct ethhdr)
				+ sizeof(struct iphdr));
	}

fail:
	return udph;
}

/* TODO understand */
__always_inline __u16 fold(__u64 sum)
{
	for (int i = 0; i < 4; i++) {
		if (sum >> 16)
			sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

/**
 * Set checksum of IP header
 */
void ip_checksum(struct iphdr *ip_headers)
{
	/* bpf_printk("original checksum = 0x%04x\n", bpf_htons(iph->check)); */
	ip_headers->check = 0;

	/*
	 * compute a checksum difference from raw buffer pointed to by from (size
	 * from_size) towards raw buffer pointed to by to (size to_size) + seed
	 * (optional)
	 *
	 * bpf_csum_diff(__be32 *from, __u32 from_size,
	 * 				 __be32 *to, __u32 to_size, __wsum seed)
	 */
	__u64 sum = bpf_csum_diff(0, 0, (unsigned int *) ip_headers, sizeof(struct iphdr), 0);
	__u16 csum = fold(sum);

	ip_headers->check = csum;

	/* ihl = Internet Header Length */
	/* iph->check = calc_checksum((__u16 *)iph, iph->ihl<<2); */
	/* bpf_printk("calculated checksum = 0x%04x\n", bpf_htons(iph->check)); */
}

/**
 * Patch IP header destination IP address and recompute header checksum
 *
 * iph: IP header to patch
 * dst_ip: destination IP to use
 */
inline void change_dst_addr(struct iphdr *ip_headers, __be32 dst_ip)
{
	ip_headers->daddr = dst_ip;
	/* bpf_printk("new destination address: %u", iph->daddr); */

	/* set checksum to 0 before calculation */
	ip_headers->check = 0;
	ip_checksum(ip_headers);
}

/*
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

static long port_rb_callback(struct bpf_dynptr *dynptr, void *ctx)
{
	struct port_rb_event *sample;

	sample = bpf_dynptr_data(dynptr, 0, sizeof(*sample));
	if (!sample) {
		return 0;
	}

	bpf_debug("port %d, blacklist = %d",
			sample->port_num, sample->type == BLACKLIST);

	/* insert hash map entry for new whitelisted port */
	bpf_map_update_elem(&port_list, &sample->port_num, &sample->type, 0);

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
 * bpf_for_each_map_elem() callback for subnet array iteration: check whether
 * the source IP belongs to the subnet with the given index.
 *
 * map: BPF map we're looping through
 * key: current key
 * value: current value
 * ctx: source IP to check subnet for (and space to store type)
 *
 * return:
 * 0: helper continues to next loop
 * 1: helper skips rest of the loops and returns
 */
static long subnet_loop_callback(void *map, const void *key,
        void *value, void *ctx)
{
    struct bpf_subnet *subnet = value;
    struct subnet_loop_ctx *loop_ctx = ctx;

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

            /* break out of loop */
            return 1;
        } else {
            /* IP does not belong to this subnet- continue iterating */
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

			/*
			if (!current_config->dry_run) {
				packet_action = XDP_DROP;
			}
			*/
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

int src_ip_action(__u32 src_ip, struct iphdr *ip_headers,
		struct config_rb_event *current_config)
{
	short *ip_list_type;
	int packet_action = UNKNOWN;

	/* look up source IP */
	ip_list_type = bpf_map_lookup_elem(&ip_list, &src_ip);

	if (ip_list_type) {
		bpf_debug("ip_list_type: %d", *ip_list_type);
		switch (*ip_list_type) {
			case BLACKLIST:
				bpf_debug("IP lookup: %ld blacklisted", src_ip);
				packet_action = handle_blacklist(src_ip, ip_headers, current_config);
				break;
			case WHITELIST:
				bpf_debug("IP lookup: %ld whitelisted", src_ip);
				packet_action = XDP_PASS;
				break;
			default:
				break;
		}
	}

	return packet_action;
}

short subnet_state(__u32 src_ip)
{
	/* set up loop callback args */
	struct subnet_loop_ctx ctx = {
		.src_ip = src_ip,
		.type = UNKNOWN
	};

	/* iterate through subnet list */
	bpf_for_each_map_elem(&subnet_list, &subnet_loop_callback, &ctx, 0);
	return ctx.type;
}

short dst_port_state(__u16 dst_port)
{
	/* translate to host byte order */
	__u16 key = bpf_ntohs(dst_port);
	short *port_type = bpf_map_lookup_elem(&port_list, &key);
	int state = UNKNOWN;

	if (port_type) {
		state = *port_type;
	}

	return state;
}

void submit_tcp_headers(struct iphdr *ip_headers, struct tcphdr *tcp_headers)
{
	struct xdp_rb_event *event;

	if (ip_headers && tcp_headers) {
		/* IP not black/whitelisted- send TCP headers to user space */

		/* reserve ring buffer sample */
		event = bpf_ringbuf_reserve(&xdp_rb, sizeof(*event), 0);
		if (!event) {
			bpf_debug("XDP ring buffer allocation failed");
			return;
		}

		/* fill out ring buffer sample */
		event->ip_header = *ip_headers;
		event->tcp_header = *tcp_headers;

		/* submit ring buffer event */
		bpf_ringbuf_submit(event, 0);
	}
}

void submit_udp_headers(struct iphdr *ip_headers, struct udphdr *udp_headers)
{
	struct xdp_rb_event *event;

	if (ip_headers && udp_headers) {
		/* IP not black/whitelisted- send TCP headers to user space */

		/* reserve ring buffer sample */
		event = bpf_ringbuf_reserve(&xdp_rb, sizeof(*event), 0);
		if (!event) {
			bpf_debug("XDP ring buffer allocation failed");
			return;
		}

		/* fill out ring buffer sample */
		event->ip_header = *ip_headers;
		event->udp_header = *udp_headers;

		/* submit ring buffer event */
		bpf_ringbuf_submit(event, 0);
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

	struct iphdr *ip_headers = NULL;
	struct tcphdr *tcp_headers = NULL;
	struct udphdr *udp_headers = NULL;

	ip_headers = parse_ip_headers(ctx);
	if (!ip_headers) {
		return packet_action;
	}

	struct config_rb_event *current_config = bpf_map_lookup_elem(&config, &CONFIG_INDEX);

	src_ip = src_addr(ip_headers);

    /*
	switch (protocol_number) {
		case ICMP_PNUM:
			bpf_debug("ICMP: src IP %ld", src_ip);
			break;
		case TCP_PNUM:
			bpf_debug("TCP: src IP %ld", src_ip);
			break;
		case UDP_PNUM:
			bpf_debug("UDP: src IP %ld", src_ip);
			break;
	}
    */

	packet_action = src_ip_action(src_ip, ip_headers, current_config);
	if (packet_action != UNKNOWN) {
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
			switch (protocol_number) {
			case TCP_PNUM:
				tcp_headers = parse_tcp_headers(ctx);
				/* check whether port is whitelisted */
				if (tcp_headers) {
					if (dst_port_state(tcp_headers->dest) == WHITELIST) {
						bpf_debug("TCP port %-5d whitelisted", bpf_ntohs(tcp_headers->dest));
					} else {
						/* bpf_debug("submitting TCP headers"); */
						submit_tcp_headers(ip_headers, tcp_headers);
					}
				}
				break;
			case UDP_PNUM:
				udp_headers = parse_udp_headers(ctx);
				/* check whether port is whitelisted */
				if (udp_headers) {
					if (dst_port_state(udp_headers->dest) == WHITELIST) {
						bpf_debug("UDP port %-5d whitelisted", bpf_ntohs(udp_headers->dest));
					} else {
						/* bpf_debug("submitting UDP headers"); */
						submit_udp_headers(ip_headers, udp_headers);
					}
				}
				break;
			}
			break;
		}
	}

	/* reset to XDP_PASS before returning */
	if (current_config) {
		if (current_config->dry_run) {
			packet_action = XDP_PASS;
		}

		/* add test result to map if packet comes from the testing subnet */
		if (current_config->test &&
				in_subnet(src_ip, current_config->test_network_addr, current_config->test_mask)) {
			bpf_map_update_elem(&test_results, &src_ip, &packet_action, 0);
		}
	}

	bpf_debug("%ld, pass = %d drop = %d, tx  = %d",
			src_ip, packet_action == XDP_PASS, packet_action == XDP_DROP, packet_action == XDP_TX);

	return packet_action;
}
