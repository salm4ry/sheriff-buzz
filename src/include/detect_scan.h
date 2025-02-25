#ifndef __DETECT_SCAN_INTERFACE
#define __DETECT_SCAN_INTERFACE

#include <linux/stddef.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <stdbool.h>

#define NUM_PORTS 65536
#define MAX_PACKETS 1024

bool is_fin_scan(struct tcphdr *tcph);
int is_xmas_scan(struct tcphdr *tcph);
int is_null_scan(struct tcphdr *tcph);
int flag_based_scan(struct tcphdr *tcp_header);

#endif
