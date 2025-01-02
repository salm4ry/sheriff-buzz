#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <stdbool.h>

#include "packet_data.h"

#define NUM_PORTS 65536
#define MAX_PACKETS 1024

/*
 * TCP connection identified by the 4-tuple:
 * (src_ip, src_port, dst_ip, dst_port)
 */
struct connection {
	/* store source IP; destination IP assumed to be localhost */
	long src_ip;
	/* nmap randomises port number by default so don't use to detect scan
	int src_port;
	*/
	/* int dst_port; */
	int packet_count; /* number of packets */
	bool ports_scanned[NUM_PORTS]; /* ports scanned (true/false) */
};

struct packet {
    int dst_port;
    bool flags[NUM_FLAGS];
};

static int count_ports_scanned(bool *ports_scanned)
{
	int port_count = 0;

	for (int i = 0; i < NUM_PORTS; i++) {
		if (ports_scanned[i]) {
			port_count++;
		}
	}

	return port_count;
}

static bool is_basic_scan(struct connection *conn, int *common_ports, int num_ports)
{
	int common_port_count = 0;
	/* int port_count = count_ports_scanned(conn); */

	for (int i = 0; i < num_ports; i++) {
		if (conn->ports_scanned[common_ports[i]]) {
			common_port_count++;
		}
	}

	return (common_port_count == num_ports);
}

/* detect nmap -sF: FIN only */
static bool is_fin_scan(struct tcphdr *tcph)
{
	/* check if FIN enabled */
	if (!get_tcp_flag(tcph, TCP_FLAG_FIN)) {
		return false;
	}

	/* iterate through flag enum */
	for (int i = SYN; i <= CWR; i++) {
		if (get_tcp_flag(tcph, i)) {
			return false;
		}
	}

	return true;
}

/* detect nmap -sX: FIN + PSH + URG */
static int is_xmas_scan(struct tcphdr *tcph) {
	return (get_tcp_flag(tcph, FIN) && get_tcp_flag(tcph, PSH) && get_tcp_flag(tcph, URG));
}

/* no flags set */
static int is_null_scan(struct tcphdr *tcph) {
	for (int i = FIN; i <= CWR; i++) {
		if (get_tcp_flag(tcph, i)) {
			return false;
		}
	}
	return true;
}
