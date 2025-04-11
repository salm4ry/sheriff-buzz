/// @file

#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <stdbool.h>

#include "include/detect_scan.h"
#include "include/packet_data.h"
#include "include/parse_headers.h"

/**
 * @brief Determine whether a set of TCP headers has FIN flag only set
 * @param tcp_headers: headers to check
 * @return true if combination set, false otherwise
 */
bool is_fin_scan(struct tcphdr *tcp_headers)
{
	/* check if FIN enabled */
	if (!tcp_flag(tcp_headers, TCP_FLAG_FIN)) {
		return false;
	}

	/* iterate through flag enum */
	for (int i = SYN; i <= CWR; i++) {
		if (tcp_flag(tcp_headers, i)) {
			return false;
		}
	}

	return true;
}

/**
 * @brief Determine whether a set of TCP headers has Xmas flags (FIN + PSH + URG) set
 * @param tcp_headers headers to check
 * @return true if combination set, false otherwise
 */
int is_xmas_scan(struct tcphdr *tcp_headers) {
	return (tcp_flag(tcp_headers, FIN) &&
		tcp_flag(tcp_headers, PSH) &&
		tcp_flag(tcp_headers, URG));
}

/**
 * @brief Determine whether a set of TCP headers has no flags set
 * @param tcp_headers headers to check
 * @return true if no flags set, false otherwise
 */
int is_null_scan(struct tcphdr *tcp_headers) {
	for (int i = FIN; i <= CWR; i++) {
		if (tcp_flag(tcp_headers, i)) {
			return false;
		}
	}
	return true;
}

/**
 * @brief Determine if a packet is part of a flag-based scan
 * @param tcp_headers headers to check
 * @param types alert types to assign
 * @return non-zero alert type if there is a scan, 0 otherwise
 */
int flag_based_scan(struct tcphdr *tcp_headers, struct alert_type types)
{
	int scan_type = 0;

	if (is_xmas_scan(tcp_headers)) {
		scan_type = types.XMAS_SCAN;
	} else if (is_fin_scan(tcp_headers)) {
		scan_type = types.FIN_SCAN;
	} else if (is_null_scan(tcp_headers)) {
		scan_type = types.NULL_SCAN;
	}

	return scan_type;
}
