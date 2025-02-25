#ifndef __BPF_COMMON_INTERFACE
#define __BPF_COMMON_INTERFACE

#include <stdbool.h>

#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <bpf/bpf_endian.h>
#include <sys/cdefs.h>

/**
 * Shared definitions between user space and BPF program
 */

#define TCP_PNUM 6 /* TCP protocol number */
#define ICMP_PNUM 1
#define NUM_PORTS 65536

/* TODO change back to 0 and 1/other sensible values */
enum ip_types {
	BLACKLIST = 0xdead,
	WHITELIST = 0xbeef
};

/**
 * XDP ring buffer event
 *
 * iph: packet IP headers
 * tcph: packet TCP headers
 * timestamp: time elapsed since system boot in nanoseconds
 */
struct xdp_rb_event {
	struct iphdr ip_header;
	struct tcphdr tcp_header;
};

/**
 * IP user ring buffer event
 *
 * src_ip: flagged source IP address
 * type: either BLACKLIST or WHITELIST
 */
struct ip_rb_event {
	__u32 src_ip;
	int type;
};

/**
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
	int type;
};

struct port_rb_event {
	__u16 port_num;
};

/**
 * Config user ring buffer event
 *
 * block_src: true = block flagged IPs, false = redirect flagged IPs
 * dry_run: should we actually block/redirect flagged IPs?
 * redirect_ip: IP address to redirect traffic from flagged IPs to
 */
struct config_rb_event {
	bool block_src;
	bool dry_run;
	__u32 redirect_ip;
};

__u32 src_addr(struct iphdr *ip_header);
bool in_subnet(__u32 ip, __u32 network_addr, __u32 mask);

#endif
