#include <linux/bpf.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <unistd.h>

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
 */
void ip_checksum(struct iphdr *iph)
{
	bpf_printk("original checksum = 0x%04x\n", bpf_htons(iph->check));
	iph->check = 0;

	/*
	 * compute a checksum difference from raw buffer pointed to by from (size
	 * from_size) towards raw buffer pointed to by to (size to_size) + seed
	 * (optional)
	 *
	 * bpf_csum_diff(__be32 *from, __u32 from_size,
	 * 				 __be32 *to, __u32 to_size, __wsum seed)
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
 * iph: IP header to patch
 * dst_ip: destination IP to use
 */
static inline void change_dst_addr(struct iphdr *iph, __be32 dst_ip)
{
	iph->daddr = dst_ip;

	/* set checksum to 0 before calculation */
	iph->check = 0;
	ip_checksum(iph);
}
