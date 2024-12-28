#include <stdbool.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#define NUM_FLAGS 8 /* excluding res1 and doff */
#define NUM_PORTS 65536

enum flag_indices {
	FIN = TCP_FLAG_FIN,
	SYN = TCP_FLAG_SYN,
	RST = TCP_FLAG_RST,
	PSH = TCP_FLAG_PSH,
	ACK = TCP_FLAG_ACK,
	URG = TCP_FLAG_URG,
	ECE = TCP_FLAG_ECE,
	CWR = TCP_FLAG_CWR,
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
