#include <linux/ip.h>

/**
 * Fold:
 *
 * 1. carry addition to get checksum down to 16 bits
 * 2. take the one's complement (bitwise NOT) to get the checksum
 *
 * implementation based on:
 * https://github.com/xdp-project/xdp-tutorial/blob/61e24d3344b43a87297a31cfa6e83171931f2f00/packet-solutions/xdp_prog_kern_03.c#L34
 */
static inline __u16 fold(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);

	/* NOTE: ~ = bitwise NOT */
	return ~sum;
}

/**
 * Patch IP header destination IP address and recompute header checksum
 *
 * iph: IP headers to patch
 * dst_ip: destination IP to use
 */
static inline void patch_iphdr(struct iphdr *iph, __be32 dst_ip)
{
	__sum16 new_checksum;

	/* set new destination address */
	iph->daddr = dst_ip;

	/* RFC791
	 * (https://datatracker.ietf.org/doc/rfc791/):
	 *
	 * The checksum field is the 16 bit one's complement of the one's
     * complement sum of all 16 bit words in the header.  For purposes of
     * computing the checksum, the value of the checksum field is zero.
	 */

	/* TODO 1) divide the header into 16-bit words */
	/* TODO 2) take the sum of the words */
	/* TODO 3) do a one's complement of the sum */
}
