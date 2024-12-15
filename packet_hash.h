#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>
#include <time.h>

#include "parse_headers.h"

/* maximum fingerprint string length */
#define MAX_FINGERPRINT 23

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

/* create string fingerprint from key struct */
void get_fingerprint(struct key *key, char *buf)
{
	/* extract flags into string form */
	char flags[NUM_FLAGS+1];
	for (int i = 0; i < NUM_FLAGS; i++) {
		flags[i] = key->flags[i] ? '1' : '0';
	}
	flags[NUM_FLAGS] = '\0';

	/* zero-padded so fingerprints are always of length MAX_FINGERPRINT */
	snprintf(buf, MAX_FINGERPRINT+1, "%010ld%05d%s", key->src_ip, key->dst_port, flags);
}

/* generate port-based fingerprints for a given source IP and flag combination */
char **gen_port_fingerprints(long src_ip, bool flags[NUM_FLAGS])
{
	char **fingerprints = malloc(NUM_PORTS * sizeof(char *));
	struct key current_key;
	current_key.src_ip = src_ip;
	memcpy(current_key.flags, flags, NUM_FLAGS);

	for (int i = 0; i < NUM_PORTS; i++) {
		current_key.dst_port = i;
		fingerprints[i] = malloc((MAX_FINGERPRINT+1) * sizeof(char));
		get_fingerprint(&current_key, fingerprints[i]);
	}

	/*
	for (int i = 0; i < NUM_PORTS; i++) {
		printf("fingerprint %d = %s\n", i, fingerprints[i]);
	}
	*/

	return fingerprints;
}

/* free per-port IP fingerprints */
void free_port_fingerprints(char **fingerprints)
{
	for (int i = 0; i < NUM_PORTS; i++) {
		free(fingerprints[i]);
	}
	free(fingerprints);
}

void gen_bitstrings(char *bitstring, char **bitstrings, int *str_index, int n)
{
	if (n == 0) {
		bitstrings[*str_index] = malloc(NUM_FLAGS+1 * sizeof(char));
		strcpy(bitstrings[*str_index], bitstring);
		bitstrings[*str_index][NUM_FLAGS] = '\0';
		*str_index = *str_index+ 1;
	} else {
		bitstring[n-1] = '0';
		gen_bitstrings(bitstring, bitstrings, str_index, n-1);
		bitstring[n-1] = '1';
		gen_bitstrings(bitstring, bitstrings, str_index, n-1);
	}
}

/* generate flag-based fingerprints for a given source IP and destination port */
char **gen_flag_fingerprints(long src_ip, int dst_port)
{
	/* 2^NUM_FLAGS possible flag combinations */
	const int NUM_FINGERPRINTS = pow(2, NUM_FLAGS);

	char **fingerprints = malloc(NUM_FINGERPRINTS * sizeof(char *));
	char *flag_strings[NUM_FINGERPRINTS];

	char null_fingerprint[MAX_FINGERPRINT+1];
	char base_fingerprint[MAX_FINGERPRINT+1];
	char bitstring_buf[NUM_FLAGS];
	int bitstring_index = 0;

	struct key current_key;
	current_key.src_ip = src_ip;
	current_key.dst_port = dst_port;
	bzero(current_key.flags, NUM_FLAGS);

	get_fingerprint(&current_key, null_fingerprint);
	strncpy(base_fingerprint, null_fingerprint, MAX_FINGERPRINT - 8);

	gen_bitstrings(bitstring_buf, flag_strings, &bitstring_index, NUM_FLAGS);

	for (int i = 0; i < 256; i++) {
		fingerprints[i] = malloc((MAX_FINGERPRINT+1) * sizeof(char));
		snprintf(fingerprints[i], MAX_FINGERPRINT+1, "%s%s", base_fingerprint, flag_strings[i]);

		free(flag_strings[i]);
	}

	for (int i = 0; i < NUM_FINGERPRINTS; i++) {
		printf("%s\n", fingerprints[i]);
	}

	return fingerprints;
}

void free_flag_fingerprints(char **fingerprints)
{
	const int NUM_FINGERPRINTS = pow(2, NUM_FLAGS);
	for (int i = 0; i < 256; i++) {
		printf("freeing fingerprint %i\n", i);
		free(fingerprints[i]);
	}
	free(fingerprints);
}
