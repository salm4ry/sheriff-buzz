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

/**
 * Ring buffer event
 *
 * iph: packet IP headers
 * tcph: packet TCP headers
 * timestamp: time elapsed since system boot in nanoseconds
 */
struct rb_event {
	struct iphdr iph;
	struct tcphdr tcph;
	unsigned long long timestamp; /* = u64 */
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

static __always_inline struct iphdr *get_ip_headers(struct xdp_md *ctx) {
	struct ethhdr *eth = NULL;
	struct iphdr *iph = NULL;

	void *data = (void *) (long) ctx->data;
	void *data_end = (void *) (long) ctx->data_end;

	if ((char *) data + sizeof(struct ethhdr) + sizeof(struct iphdr)
			> (char *) data_end) {
		goto fail;
	}

	eth = (struct ethhdr *) data;

	if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
		iph = (struct iphdr *) ((char *) data + sizeof(struct ethhdr));
	}

fail:
	return iph;
}

static __always_inline struct tcphdr *get_tcp_headers(struct xdp_md *ctx) {
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
