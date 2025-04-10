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

/* Shared definitions between user space and BPF program */

#define TCP_PNUM 6   /* TCP protocol number */
#define UDP_PNUM 17  /* UDP protocol number */
#define ICMP_PNUM 1  /* ICMP protocol number */
#define NUM_PORTS 65536

/* packet processing values */
#define WHITELIST 0xaa
#define BLACKLIST 0xab
#define UNKNOWN 0xac

/*
 * XDP ring buffer event
 *
 * ip_header: packet IP headers
 * tcp_header: packet TCP headers
 * udp_header: packet UDP headers
 */
struct xdp_rb_event {
	struct iphdr ip_header;
	struct tcphdr tcp_header;
	struct udphdr udp_header;
};

/*
 * IP user ring buffer event
 *
 * src_ip: source IP address to add to list
 * type: either BLACKLIST or WHITELIST
 */
struct ip_rb_event {
	__u32 src_ip;
	short type;
};

/*
 * Subnet user ring buffer event
 *
 * network_addr: subnet network address
 * mask: subnet mask
 * index: subnet array index (calculated in user space)
 * type: either BLACKLIST or WHITELIST
 */
struct subnet_rb_event {
	in_addr_t network_addr;
	in_addr_t mask;
	int index;
	short type;
};

/*
 * Port user ring buffer event
 *
 * port_num: port number
 * type: either BLACKLIST or WHITELIST
 */
struct port_rb_event {
	__u16 port_num;
	short type;
};

/*
 * Config user ring buffer event
 *
 * block_src: true = block flagged IPs, false = redirect flagged IPs
 * dry_run: should we actually block/redirect flagged IPs?
 * test: are we in testing mode?
 * redirect_ip: IP address to redirect traffic from flagged IPs to
 * test_network_addr: testing subnet network address
 * test_mask: testing subnet mask
 */
struct config_rb_event {
	bool block_src;
	bool dry_run;
	bool test;
	__u32 redirect_ip;
	in_addr_t test_network_addr;
	in_addr_t test_mask;
};

__u32 src_addr(struct iphdr *ip_header);

/* Determine if a given IP belongs to a given subnet
 *
 * ip: IP address to test
 * network_addr: network address of subnet
 * mask: subnet mask
 */
static __always_inline bool in_subnet(__u32 ip, __u32 network_addr, __u32 mask)
{
	return (ip & network_addr) == (ip & mask);
}

#endif
