#ifndef __HEADERS_INTERFACE
#define __HEADERS_INTERFACE

#include <stdbool.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
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


__u8 protocol_num(struct iphdr *ip_header);
__u32 src_addr(struct iphdr *ip_header);
bool tcp_flag(struct tcphdr *tcp_header, __be32 flag);
__u16 tcp_dst_port(struct tcphdr *tcp_header);
__u16 udp_dst_port(struct udphdr *udp_header);

#endif
