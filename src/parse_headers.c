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

/* get flag value 0/1 from TCP headers
 * flag = TCP_FLAG_xxx (defined in <linux/tcp.h) */
bool get_tcp_flag(struct tcphdr *tcph, __be32 flag)
{
	__u32 flag_val = 0xdead;
	flag_val = tcp_flag_word(tcph) & (flag);
	return (flag_val == flag);
}

/* get source port from TCP headers */
/*
__u16 get_src_port(struct tcphdr *tcph)
{
	return ntohs(tcph->source);
}
*/

/* get destination port from TCP headers */
__u16 get_dst_port(struct tcphdr *tcph)
{
	return ntohs(tcph->dest);
}
