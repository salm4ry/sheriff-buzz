#include <linux/if_link.h>
#include <stdio.h>
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
 * latest: timestamp of latest packet received
 * count: number of packets received
 */
struct value {
	time_t first;
	time_t latest;
	int count;
};

/**
 * Hash map entry
 *
 * key: hash map key
 * val: hash map value
 * next: pointer to next entry in linked list
 */
struct entry {
	struct key key;
	struct value val;
	struct entry *next;
};

/**
 * Packet hash map
 *
 * entries: array of linked lists (separate chaining)
 * NUM_SLOTS: number of linked lists in entries
 * CAPACITY: maximum number of key:value entries (nodes)
 * size: current number of entries (cannot exceed CAPACITY)
 */
struct hash_map {
	struct entry **entries;
	const int NUM_SLOTS;
	const int CAPACITY;
	int size;
};

/* concatenate struct members into key */
void get_fingerprint(struct key *key, char *buf)
{
	/* extract flags into string form */
	char flags[NUM_FLAGS+1];
	for (int i = 0; i < NUM_FLAGS; i++) {
		flags[i] = key->flags[i] ? '1' : '0';
	}
	flags[NUM_FLAGS-1] = '\0';

	sprintf(buf, "%ld%d%s", key->src_ip, key->dst_port, flags);
}
