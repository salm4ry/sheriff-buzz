#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#define MAX_IP 16

/**
 * Calculate IP header checksum for count bytes beginning at location addr
 *
 * addr = 16-bit (unsigned short) starting location
 * count = 32-bit (unsigned int) accumulator
 */
int calc_checksum(unsigned short *addr, unsigned int count)
{
	register long sum = 0;

	/* sum all 16-bit (unsigned short) words */
	while (count > 1) {
		sum += (unsigned short) *addr++;
		count -= 2;
	}

	/* pad and add left-over bytes if any */
	if (count > 0) {
		sum += * (unsigned char *) addr;
	}

	/* fold 32-bit sum to 16 bits */
	while (sum>>16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	/* ~ = bitwise NOT */
	return ~sum;
}


/**
 * Set checksum of IP header
 *
 * original and calculated checksums should be equal!
 */
void ip_checksum(struct iphdr *iph)
{
	printf("original checksum = 0x%04x\n", htons(iph->check));
	iph->check = 0;

	/* ihl = Internet Header Length */
	iph->check = calc_checksum((unsigned short *)iph, iph->ihl<<2);
	printf("calculated checksum = 0x%04x\n", htons(iph->check));
}

/**
 * Change IP packet header destination address
 */
void change_dst_addr(struct iphdr *iph, long dest_ip) {
	iph->daddr = dest_ip;
	/* set checksum to 0 before calculation */
	iph->check = 0;
	ip_checksum(iph);
}

int main(int argc, char *argv[])
{
	/* example IP header to test checksum calculation (checksum is 0xb1e6)
	 * source: https://www.thegeekstuff.com/2012/05/ip-header-checksum/ 
	 *
	 * stored as unsigned char[] since sizeof(unsigned char) = 1 */
	unsigned char header_bytes[] = {0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
		0x40, 0x06, 0xb1, 0xe6, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c};
	struct iphdr *header = (struct iphdr *) &header_bytes;
	char old_dst_addr[MAX_IP], new_dst_addr[MAX_IP];
	in_addr_t new_dest_ip;

	/* calculate IP checksum */
	ip_checksum(header);

	strncpy(new_dst_addr, "1.2.3.4", MAX_IP);
	inet_ntop(AF_INET, &header->daddr, old_dst_addr, MAX_IP);
	inet_pton(AF_INET, new_dst_addr, &new_dest_ip);

	printf("\noriginal dst IP: %s\nnew dst IP: %s\n", 
			old_dst_addr, new_dst_addr);

	/* change destination IP address */
	change_dst_addr(header, new_dest_ip);

	return 0;
}
