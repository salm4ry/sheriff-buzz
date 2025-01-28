#include <stdlib.h>
#include <stdbool.h>

#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <bpf/bpf_endian.h>
#include <sys/cdefs.h>

#define TCP_PNUM 6 /* TCP protocol number */
#define NUM_PORTS 65536

enum ip_types {
	BLACKLIST = 0xdead,
	WHITELIST = 0xbeef
};


/**
 * XDP ring buffer event
 *
 * iph: packet IP headers
 * tcph: packet TCP headers
 * timestamp: time elapsed since system boot in nanoseconds
 */
struct xdp_rb_event {
	struct iphdr ip_header;
	struct tcphdr tcp_header;
};

/**
 * IP user ring buffer event
 *
 * src_ip: flagged source IP address
 * type: either BLACKLIST or WHITELIST
 */
struct ip_rb_event {
	__u32 src_ip;
	int type;
};

/**
 * Config user ring buffer event
 *
 * block_src: true = block flagged IPs, false = redirect flagged IPs
 * redirect_ip: IP address to redirect traffic from flagged IPs to
 */
struct config_rb_event {
	bool block_src;
	__u32 redirect_ip;
};

/* return the protocol byte for an IP packet, 0 for anything else
 * adapted from: https://github.com/lizrice/ebpf-beginners/blob/main/packet.h */
static __always_inline __u8 lookup_protocol(struct xdp_md *ctx)
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

static __always_inline struct iphdr *parse_ip_headers(struct xdp_md *ctx) {
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

static __always_inline struct tcphdr *parse_tcp_headers(struct xdp_md *ctx) {
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

/* get IP packet source address */
static __u32 src_addr(struct iphdr *ip_header)
{
	return ip_header->saddr;
}

/**
 * Return whether a given IP belongs to the specified subnet
 * NOTE: all values are in network (big-endian) byte order
 *
 * ip = IP address to check
 * network_addr = network address of subnet
 * mask = subnet mask
 */
static bool in_subnet(__u32 ip, __u32 network_addr, __u32 mask)
{
	return (ip & network_addr) == (ip & mask);
}
