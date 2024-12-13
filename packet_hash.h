#include <time.h>
#include "parse_headers.h"

/**
 * Hash table key
 *
 * src_ip: source IP address
 * dst_port: destination port
 * flags: TCP flags
 */
struct key {
	long src_ip;
	int dst_port;
	bool flags[NUM_FLAGS];
};

/**
 * Hash table value
 *
 * first: timestamp of first packet received
 * latest: timestamp of last packet received
 * count: number of packets received
 */
struct value {
	time_t first;
	time_t latest;
	int count;
};
