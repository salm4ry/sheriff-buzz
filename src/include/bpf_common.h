/**
 * @file
 * @brief Shared definitions between user space and BPF program
 */

#ifndef __BPF_COMMON_INTERFACE
#define __BPF_COMMON_INTERFACE

#include <stdbool.h>

#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <bpf/bpf_endian.h>
#include <sys/cdefs.h>

#define TCP_PNUM 6  ///< TCP protocol number
#define UDP_PNUM 17  ///< UDP protocol number
#define ICMP_PNUM 1  ///< ICMP protocol number
#define NUM_PORTS 65536  ///< number of TCP/UDP ports

/* packet processing values */
#define WHITELIST 0xaa  ///< whitelisted packet state
#define BLACKLIST 0xab  ///< blacklisted packet state
#define UNKNOWN 0xac  ///< unknown packet state/action

/**
 * @struct xdp_rb_event
 * @brief XDP ring buffer event
 */
struct xdp_rb_event {
	struct iphdr ip_header;  ///< packet IP headers
	struct tcphdr tcp_header;  ///< packet TCP headers
	struct udphdr udp_header;  ///< packet UDP headers
};

/**
 * @struct ip_rb_event
 * @brief IP user ring buffer event
 */
struct ip_rb_event {
	__u32 src_ip;  ///< source IP address to add to list
	short type;  ///< either BLACKLIST or WHITELIST
};

/**
 * @struct subnet_rb_event
 * @brief Subnet user ring buffer event
 */
struct subnet_rb_event {
	in_addr_t network_addr;  ///< subnet network address
	in_addr_t mask;  ///< subnet mask
	int index;  ///< subnet array index (calculated in user space)
	short type;  ///< either BLACKLIST or WHITELIST
};

/**
 * @struct port_rb_event
 * @brief Port user ring buffer event
 */
struct port_rb_event {
	__u16 port_num;  ///< port number
	short type;  ///< either BLACKLIST or WHITELIST
};

/**
 * @struct config_rb_event
 * @brief Config user ring buffer event
 */
struct config_rb_event {
	bool block_src;  ///< true = block, false = redirect
	bool dry_run;  ///< are we in dry run mode?
	bool test;  ///< are we in testing mode?
	__u32 redirect_ip;  ///< IP address to redirect blacklisted traffic to
	in_addr_t test_network_addr;  ///< testing subnet network address
	in_addr_t test_mask;  ///< testing subnet mask
};

__u32 src_addr(struct iphdr *ip_header);

/**
 * @brief Determine if a given IP belongs to a given subnet
 * @param ip IP address to test
 * @param network_addr network address of subnet
 * @param mask subnet mask
 * @return true if the IP belongs, false otherwise
 */
static __always_inline bool in_subnet(__u32 ip, __u32 network_addr, __u32 mask)
{
	return (ip & network_addr) == (ip & mask);
}

#endif
