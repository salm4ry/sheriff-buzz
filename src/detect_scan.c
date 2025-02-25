#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <stdbool.h>

#include "include/detect_scan.h"
#include "include/packet_data.h"
#include "include/parse_headers.h"

#define NUM_PORTS 65536
#define MAX_PACKETS 1024


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
