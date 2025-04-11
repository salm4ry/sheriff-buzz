/// @file

#ifndef __DETECT_SCAN_INTERFACE
#define __DETECT_SCAN_INTERFACE

#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <stdbool.h>

#include "packet_data.h"

#define NUM_PORTS 65536  ///< number of TCP/UDP ports

bool is_fin_scan(struct tcphdr *tcp_headers);
int is_xmas_scan(struct tcphdr *tcp_headers);
int is_null_scan(struct tcphdr *tcp_headers);
int flag_based_scan(struct tcphdr *tcp_headers, struct alert_type types);

#endif
