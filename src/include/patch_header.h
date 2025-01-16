#include <linux/bpf.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <unistd.h>

/**
 * Calculate IP header checksum for count bytes beginning at location addr
 *
 * addr = 16-bit (unsigned short) starting location
 * count = 32-bit (unsigned int) accumulator
 */
/*
__sum16 calc_checksum(__u16 *addr, __u16 count)
{
	register __u32 sum = 0;

	// sum all 16-bit (unsigned short) words
	while (count > 1) {
		sum += *addr++;

		if (count >= 2)
			count -= 2;
		else
			break;
	}

	// TODO overflow check (unsigned int)

	// pad and add left-over bytes if any
	if (count != 0) {
		sum += * (__u8 *) addr;
	}

	// fold 32-bit sum to 16 bits
	while (sum>>16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// ~ = bitwise NOT
	return ~sum;
}
*/

static __always_inline __u16 fold(__u64 sum)
{
	for (int i = 0; i < 4; i++) {
		if (sum >> 16)
			sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

/**
 * Set checksum of IP header
 *
 * original and calculated checksums should be equal!
 */
void ip_checksum(struct iphdr *iph)
{
	bpf_printk("original checksum = 0x%04x\n", bpf_htons(iph->check));
	iph->check = 0;

	/*
	 * compute a checksum different from 
	 */
	__u64 sum = bpf_csum_diff(0, 0, (unsigned int *) iph, sizeof(struct iphdr), 0);
	__u16 csum = fold(sum);

	iph->check = csum;

	/* ihl = Internet Header Length */
	/* iph->check = calc_checksum((__u16 *)iph, iph->ihl<<2); */
	bpf_printk("calculated checksum = 0x%04x\n", bpf_htons(iph->check));
}

/**
 * Patch IP header destination IP address and recompute header checksum
 *
 * iph: IP headers to patch
 * dst_ip: destination IP to use
 */
static inline void change_dst_addr(struct iphdr *iph, __be32 dst_ip)
{
	iph->daddr = dst_ip;
	/* set checksum to 0 before calculation */
	iph->check = 0;
	ip_checksum(iph);
}
