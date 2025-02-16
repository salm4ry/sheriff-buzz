#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <stdbool.h>
#include <string.h>

#include "packet_data.h"

#define NUM_PORTS 65536
#define MAX_PACKETS 1024

/*
bool is_port_scan(bool *ports_scanned, int threshold)
{
	int port_count = count_ports_scanned(ports_scanned);

	// TODO use common port count as well as overall port count
	int common_port_count = 0;

	for (int i = 0; i < NUM_PORTS; i++) {
		if (ports_scanned[common_ports[i]]) {
			common_port_count++;
		}
	}

	return (port_count >= threshold);
}
*/

bool use_db_thread;

/* detect nmap -sF: FIN only */
bool is_fin_scan(struct tcphdr *tcph)
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
int is_xmas_scan(struct tcphdr *tcph) {
	return (get_tcp_flag(tcph, FIN) && get_tcp_flag(tcph, PSH) && get_tcp_flag(tcph, URG));
}

/* no flags set */
int is_null_scan(struct tcphdr *tcph) {
	for (int i = FIN; i <= CWR; i++) {
		if (get_tcp_flag(tcph, i)) {
			return false;
		}
	}
	return true;
}

int flag_based_scan(struct tcphdr *tcp_header)
{
	int scan_type = 0;

	if (is_xmas_scan(tcp_header)) {
		scan_type = XMAS_SCAN;
	} else if (is_fin_scan(tcp_header)) {
		scan_type = FIN_SCAN;
	} else if (is_null_scan(tcp_header)) {
		scan_type = NULL_SCAN;
	}

	return scan_type;
}
