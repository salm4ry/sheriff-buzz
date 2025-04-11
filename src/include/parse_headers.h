/// @file

#ifndef __HEADERS_INTERFACE
#define __HEADERS_INTERFACE

#include <stdbool.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>

#define NUM_FLAGS 8  ///< number of TCP header flags (excluding res1 and doff)
#define NUM_PORTS 65536  ///< number of TCP/UDP ports

/**
 * @brief Enum to iterate over when checking TCP header flags
 */
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


__u8 protocol_num(struct iphdr *ip_headers);
__u32 src_addr(struct iphdr *ip_headers);
bool tcp_flag(struct tcphdr *tcp_headers, __be32 flag);
__u16 tcp_dst_port(struct tcphdr *tcp_headers);
__u16 udp_dst_port(struct udphdr *udp_headers);

#endif
