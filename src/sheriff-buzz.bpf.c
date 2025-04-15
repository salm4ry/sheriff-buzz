/// @file

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

char LICENSE[] SEC("license") = "GPL";

/**
 * @struct subnet_entry
 * @brief Subnet list entry
 */
struct subnet_entry {
	in_addr_t network_addr; ///< subnet address
	in_addr_t mask;  ///< subnet mask
	short type;  ///< BLACKLIST/WHITELIST
};

/**
 * @brief Subnet iteration context
 * @details Used as context to bpf_for_each_map_elem()
 */
struct subnet_loop_ctx {
	in_addr_t src_ip; ///< source IP
	short type;  ///< BLACKLIST/WHITELIST/UNDEFINED
};

/**
 * @struct ip_list
 * @brief IP hash map
 * @details Stores blacklisted and whitelisted IPs (key = source IP, value =
 * BLACKLIST/WHITELIST
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, short);
	__uint(max_entries, 16384);
} ip_list SEC(".maps");

/**
 * @struct subnet_list
 * @brief Subnet array
 * @details Stores blacklisted and whitelisted subnets (key = array index, value
 * = bpf_subnet)
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct subnet_entry);
	__uint(max_entries, 128);
} subnet_list SEC(".maps");

/**
 * @struct port_list
 * @brief Port hash map
 * @details Stores whitelisted ports (key = destination port,
 * value = WHITELIST only)
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u16);
	__type(value, short);
	__uint(max_entries, 1024);
} port_list SEC(".maps");

/**
 * @struct config
 * @brief Config array
 * @details One-element array to store current action configuration in the value
 * field
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct config_rb_event);
	__uint(max_entries, 1);
} config SEC(".maps");

/**
 * @struct test_results
 * @brief XDP unit test result hash map
 * @details Store test subnet XDP return values (key = source IP, value = XDP
 * return value)
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, __u16);
	__uint(max_entries, 128);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} test_results SEC(".maps");

/**
 * @struct xdp_rb
 * @brief Kernel ring buffer used by XDP program
 * @details Send TCP headers from kernel -> user space (struct xdp_rb_event)
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, (8 * 1024) * 1024); /* 8 MB */
} xdp_rb SEC(".maps");

/**
 * @struct ip_rb
 * @brief IP user ring buffer
 * @details Send black/whitelisted IPs from user -> kernel space (struct ip_rb_event)
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} ip_rb SEC(".maps");

/**
 * @struct subnet_rb
 * @brief Subnet user ring buffer
 * @details Send black/whitelisted subnets from user -> kernel space
 * (struct subnet_rb_event)
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} subnet_rb SEC(".maps");

/**
 * @struct port_rb
 * @brief Port user ring buffer
 * @details Send whitelisted ports from user -> kernel space (struct port_rb_event)
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB  */
} port_rb SEC(".maps");

/**
 * @struct config_rb
 * @brief Config user ring buffer
 * @details Send configuration (e.g. block/redirect) from user -> kernel space
 * (struct config_rb_event)
 */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024); /* 256 KB */
} config_rb SEC(".maps");


/**
 * @brief Print to kernel trace log (/sys/kernel/tracing/trace_pipe)
 * @param fmt format string
 * @param ... format arguments
 * @details Only print when compiled with -DDEBUG
 */
#ifdef DEBUG
	#define bpf_debug(fmt, ...)  \
		bpf_printk(fmt, ##__VA_ARGS__);
#else
	#define bpf_debug(fmt, ...) \
		;
#endif

/**
 * @brief Get source IP address from IP headers
 * @param ip_headers IP headers
 * @return source IP address
 */
__u32 src_addr(struct iphdr *ip_headers)
{
	return ip_headers->saddr;
}

/**
 * @brief Look up packet protocol number
 * @param ctx XDP context (raw packet data)
 * @return protocol number on success, 0 on error
 */
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

/**
 * @brief Parse IP headers
 * @param ctx XDP context (raw packet data)
 * @return IP headers on success, NULL on error
 */
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

/**
 * @brief Parse TCP headers
 * @param ctx XDP context (raw packet data)
 * @return TCP headers on success, NULL on error
 */
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

/**
 * @brief Parse UDP headers
 * @param ctx XDP context (raw packet data)
 * @return UDP headers on success, NULL on error
 */
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

/**
 * @brief Fold 64-bit checksum into 16 bits by adding the 16-bit segments
 * @param sum original 64-bit checksum
 * @return 16-bit checksum
 * @details based on RFC1071 (https://datatracker.ietf.org/doc/html/rfc1071) implementation
 */
__always_inline __u16 fold(__u64 sum)
{
	for (int i = 0; i < 4; i++) {
		if (sum >> 16)
			sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

/**
 * @brief Set IP header checksum
 * @param ip_headers IP headers
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
}

/**
 * @brief Change IP header destination IP address and recompute header checksum
 * @param iph IP header to alter
 * @param dst_ip new destination IP
 */
inline void change_dst_addr(struct iphdr *ip_headers, __be32 dst_ip)
{
	ip_headers->daddr = dst_ip;
	/* bpf_printk("new destination address: %u", iph->daddr); */

	/* set checksum to 0 before calculation */
	ip_headers->check = 0;
	ip_checksum(ip_headers);
}

/**
 * @brief IP user ring buffer callback: add IP sent from user space to list
 * @param dynptr pointer to ring buffer sample
 * @param ctx context from bpf_user_ringbuf_drain() (unused)
 * @return 0 so that bpf_user_ringbuf_drain() continues to drain samples
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

/**
 * @brief Subnet user ring buffer callback: Add subnet sent from user space to
 * list
 * @param dynptr pointer to ring buffer sample
 * @param ctx context from bpf_user_ringbuf_drain() (unused)
 * @return 0 so that bpf_user_ringbuf_drain() continues to drain samples
 */
static long subnet_rb_callback(struct bpf_dynptr *dynptr, void *ctx)
{
    struct subnet_rb_event *sample;
    struct subnet_entry subnet;

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

/**
 * @brief Port user ring buffer callback: Add port sent from user space to list
 * @param dynptr pointer to ring buffer sample
 * @param ctx context from bpf_user_ringbuf_drain() (unused)
 * @return 0 so that bpf_user_ringbuf_drain() continues to drain samples
 */
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
/**
 * @brief Config user ring buffer callback: Update config map with configuration
 * sent from user space
 * @param dynptr: pointer to ring buffer sample
 * @param ctx: context from bpf_user_ringbuf_drain() (unused)
 * @return 0 so that bpf_user_ringbuf_drain() continues to drain samples
 */

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
 * @brief Check whether the source IP belongs to the subnet with the given index
 * @param map BPF map we're looping through
 * @param key current key
 * @param value current value
 * @param ctx source IP to check subnet for (and space to store type)
 * @return 1 when subnet found, 0 otherwise
 * @details bpf_for_each_map_elem() callback for subnet array iteration.
 * Returning 0 makes the helper continue to the next iteration, returning 1 makes the
 * helper skip the rest of the iterations and returns
 */

static long subnet_loop_callback(void *map, const void *key,
        void *value, void *ctx)
{
    struct subnet_entry *subnet = value;
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

/**
 * @brief Determine the XDP return value for a packet from a blacklisted source
 * @param src_ip source IP
 * @param ip_headers IP headers
 * @param current_config current action configuration
 * @return XDP_DROP (blocking), XDP_TX (redirection after changing
 * destination IP), XDP_PASS (dry run mode)
 */
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

/**
 * @brief Get the packet action for a source IP based on ip_list
 * @param src_ip source IP
 * @param ip_headers IP headers
 * @param current_config current action configuration
 * @return XDP_PASS (whitelisted), XDP_DROP/XDP_TX (blacklisted), or UNKNOWN
 * @details Look up the source IP to determine whether it's whitelisted,
 * blacklisted, or unknown
 */
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

/**
 * @brief Determine the state of an IP based on subnet_list
 * @param src_ip source IP
 * @return BLACKLIST, WHITELIST, or UNKNOWN (no matching subnet found)
 * @details Iterate through the subnet map, testing whether the IP belongs
 */
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

/**
 * @brief Determine the state of a destination port based on port_list
 * @param dst_port destination port
 * @return BLACKLIST, WHITELIST, or UNKNOWN
 */
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

/**
 * @brief Send IP & TCP headers to user space through the XDP ring buffer
 * @param ip_headers IP headers
 * @param tcp_headers TCP headers
 */
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

/**
 * @brief Send IP & UDP headers to user space through the XDP ring buffer
 * @param ip_headers IP headers
 * @param udp_headers UDP headers
 */
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

/**
 * @brief Read ip_rb samples when they are submitted from user space
 * @return 0
 */
SEC("uretprobe")
int read_ip_rb()
{
	bpf_user_ringbuf_drain(&ip_rb, ip_rb_callback, NULL, 0);
	return 0;
}

/**
 * @brief Read subnet_rb samples when they are submitted from user space
 * @return 0
 */
SEC("uretprobe")
int read_subnet_rb()
{
    bpf_user_ringbuf_drain(&subnet_rb, subnet_rb_callback, NULL, 0);
    return 0;
}

/**
 * @brief Read port_rb samples when they are submitted from user space
 * @return 0
 */
SEC("uretprobe")
int read_port_rb()
{
	bpf_user_ringbuf_drain(&port_rb, port_rb_callback, NULL, 0);
	return 0;
}

/**
 * @brief Read config_rb samples when they are submitted from user space
 * @return 0
 */
SEC("uretprobe")
int read_config_rb()
{
	bpf_user_ringbuf_drain(&config_rb, config_rb_callback, NULL, 0);
	return 0;
}

/**
 * @brief Process packets, applying actions based on blacklist, whitelist, and
 * configuration maps
 * @param ctx XDP context (raw packet data)
 * @return XDP_PASS when packet whitelisted/unknown, XDP_DROP ("block") or
 * XDP_TX ("redirect") when blacklisted
 */
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
