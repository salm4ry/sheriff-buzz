/// @file

#include <stdbool.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#include "include/parse_headers.h"

/**
 * @brief Get source IP address from IP headers
 * @param ip_headers IP headers
 * @return source IP address
 */
__u32 src_addr(struct iphdr *ip_headers)
{
	return ip_headers->saddr;
}

/**
 * @brief Get protocol number from IP headers
 * @param ip_headers IP headers
 * @return protocol number
 */
__u8 protocol_num(struct iphdr *ip_headers)
{
	return ip_headers->protocol;
}

/**
 * @brief Get flag value from TCP headers
 * @param tcp_headers TCP headers
 * @param flag `TCP_FLAG_xxx` (defined in `<linux/tcp.h>`)
 * @return 1 if flag is set, 0 otherwise
 */
bool tcp_flag(struct tcphdr *tcp_headers, __be32 flag)
{
	__u32 flag_val = 0xdead;
	flag_val = tcp_flag_word(tcp_headers) & (flag);
	return (flag_val == flag);
}

/**
 * @brief Get destination port from TCP headers
 * @param tcp_headers TCP headers
 * @return TCP destination port
 */
__u16 tcp_dst_port(struct tcphdr *tcp_headers)
{
	return ntohs(tcp_headers->dest);
}

/**
 * @brief Get destination port from UDP headers
 * @param udp_headers UDP headers
 * @return UDP destination port
 */
__u16 udp_dst_port(struct udphdr *udp_headers)
{
    return ntohs(udp_headers->dest);
}
