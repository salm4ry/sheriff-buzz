#include <stdbool.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#define NUM_FLAGS 8 /* excluding res1 and doff */
#define NUM_PORTS 65536

#include "include/parse_headers.h"

__u32 src_addr(struct iphdr *ip_header)
{
	return ip_header->saddr;
}

__u8 protocol_num(struct iphdr *ip_header)
{
    return ip_header->protocol;
}

/* get flag value 0/1 from TCP headers
 * flag = TCP_FLAG_xxx (defined in <linux/tcp.h) */
bool tcp_flag(struct tcphdr *tcp_header, __be32 flag)
{
	__u32 flag_val = 0xdead;
	flag_val = tcp_flag_word(tcp_header) & (flag);
	return (flag_val == flag);
}

/* get destination port from TCP headers */
__u16 tcp_dst_port(struct tcphdr *tcp_header)
{
	return ntohs(tcp_header->dest);
}

/* get destination port from UDP headers */
__u16 udp_dst_port(struct udphdr *udp_header)
{
    return ntohs(udp_header->dest);
}
