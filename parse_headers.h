#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#define NUM_FLAGS 8 /* excluding res1 and doff */

enum flag_indices {
	FIN,
	SYN,
	RST,
	PSH,
	ACK,
	URG,
	ECE,
	CWR,
};

/* get IP packet source address */
static __u32 get_source_addr(struct iphdr *iph)
{
	return ntohl(iph->saddr);
}

/* get flag value 0/1 from TCP headers
 * flag = TCP_FLAG_xxx (defined in <linux/tcp.h) */
static bool get_tcp_flag(struct tcphdr *tcph, __be32 flag)
{
	__u32 flag_val = 0xdead;
	flag_val = tcp_flag_word(tcph) & (flag);
	return (flag_val == flag);
}

/* get source port ffrom TCP headers */
static __u16 get_src_port(struct tcphdr *tcph)
{
	return ntohs(tcph->source);
}

/* get destination port from TCP headers */
static __u16 get_dst_port(struct tcphdr *tcph)
{
	return ntohs(tcph->dest);
}
