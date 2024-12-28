#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
/* #include <math.h> */

#include <bpf/libbpf.h>
#include <glib-2.0/glib.h>
#include <postgresql/libpq-fe.h>

#include "parse_headers.h"

/* maximum fingerprint string length */
#define MAX_FINGERPRINT 13
#define MAX_QUERY 512
#define MAX_IP 16

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
	/* bool flags[NUM_FLAGS]; */
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
	/*
	bool should_be_logged;
	bool logged;
	*/
};

/* create string fingerprint from key struct */
void get_fingerprint(struct key *key, char *buf)
{
	/* extract flags into string form */
	/*
	char flags[NUM_FLAGS+1];
	for (int i = 0; i < NUM_FLAGS; i++) {
		flags[i] = key->flags[i] ? '1' : '0';
	}
	flags[NUM_FLAGS] = '\0';
	*/

	/* zero-padded so fingerprints are always of length MAX_FINGERPRINT */
	/* snprintf(buf, MAX_FINGERPRINT+1, "%010ld%05d%s", key->src_ip, key->dst_port, flags); */
	snprintf(buf, MAX_FINGERPRINT, "%08lx%04x", key->src_ip, key->dst_port);
}

/* generate port-based fingerprints for a given source IP and flag combination */
char **gen_port_fingerprints(long src_ip)
{
	char **fingerprints = malloc(NUM_PORTS * sizeof(char *));
	struct key current_key;
	current_key.src_ip = src_ip;
	/* memcpy(current_key.flags, flags, NUM_FLAGS); */

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

/*
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

// generate flag-based fingerprints for a given source IP and destination port
char **gen_flag_fingerprints(long src_ip, int dst_port)
{
	// 2^NUM_FLAGS possible flag combinations
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
	for (int i = 0; i < NUM_FINGERPRINTS; i++) {
		printf("freeing fingerprint %i\n", i);
		free(fingerprints[i]);
	}
	free(fingerprints);
}
*/

/* log alert to database, replacing old record if necessary */
int log_alert(PGconn *db_conn, char *fingerprint, int alert_type, struct key *key, struct value *value)
{
	PGresult *db_res;
	int err;
	char query[MAX_QUERY];
	char ip_str[MAX_IP];

	/* alert already in database */
	/*
	if (value->logged) {
		return 0;
	}
	*/

	/* char *delete_command = "DELETE FROM log WHERE fingerprint = '%s' AND alert_type = %d"; */
	/* TODO increment count if this is the first log of this alert for a given program run */
	char *insert_command = "INSERT INTO log (fingerprint, dst_port, alert_type, src_ip, packet_count, first, latest) "
				   		   "VALUES ('%s', %d, %d, '%s', %d, to_timestamp(%ld), to_timestamp(%ld)) "
						   "ON CONFLICT (fingerprint, alert_type) DO UPDATE "
						   "SET packet_count=%d, latest=to_timestamp(%ld)";

	long src_ip = ntohl(key->src_ip);

	inet_ntop(AF_INET, &src_ip, ip_str, MAX_IP);

	/* remove old entries from log */
	/*
	sprintf(query, delete_command, fingerprint, alert_type);
	printf("%s\n", query);
	db_res = PQexec(db_conn, query);
	if (PQresultStatus(db_res) != PGRES_COMMAND_OK) {
		fprintf(stderr, "postgres: %s\n", PQerrorMessage(db_conn));
	}
	PQclear(db_res);
	*/

	sprintf(query, insert_command, fingerprint, key->dst_port, alert_type,
			ip_str, value->count, value->first, value->latest,
			value->count, value->latest);
	printf("%s\n", query);

	db_res = PQexec(db_conn, query);
	err = (PQresultStatus(db_res) == PGRES_COMMAND_OK);

	if (!err) {
		fprintf(stderr, "postgres: %s\n", PQerrorMessage(db_conn));
	}

	PQclear(db_res);

	/* mark hash table entry as logged */
	/* value->logged = true; */
	return err;
}

/* connect to postgres database with peer authentication
 * (postgres username = system username) */
static PGconn *connect_db(char *user, char *dbname)
{
	char query[1024];

	sprintf(query, "user=%s dbname=%s", user, dbname);
	PGconn *conn = PQconnectdb(query);
	if (PQstatus(conn) == CONNECTION_BAD) {
		fprintf(stderr, "connection to database failed: %s\n",
				PQerrorMessage(conn));
		PQfinish(conn);
		/* return NULL on error */
		return NULL;
	}

	return conn;
}

void update_record(gpointer key, gpointer value, gpointer user_data)
{
	struct value *val = (struct value *) value;

	char *fingerprint = key;
	PGconn *db_conn = (PGconn *) user_data;

	/* convert to UNIX time for current fingerprint */
	char *lookup_cmd = "SELECT packet_count FROM log WHERE fingerprint = '%s'";
	char *update_cmd = "UPDATE log SET packet_count = %d, latest = to_timestamp(%ld) "
					   "WHERE fingerprint = '%s'\n";

	char lookup_query[MAX_QUERY], update_query[MAX_QUERY];
	PGresult *res;

	int db_count;
	int table_count = val->count;
	/* int rows; */

	/* only consider entries logged in database */
	/*
	if (!val->logged) {
		return;
	}
	*/

	sprintf(lookup_query, lookup_cmd, fingerprint);
	printf("%s\n", lookup_query);

	res = PQexec(db_conn, lookup_query);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		fprintf(stderr, "postgres: %s\n", PQerrorMessage(db_conn));
		return;
	}

	/* compare database and hash table timestamps
	 * only one tuple (record) and field (latest) */
	/*
	rows = PQntuples(res);
	if (rows == 0) {
		return;
	}
	*/

	db_count = atoi(PQgetvalue(res, 0, 0));
	PQclear(res);
	if (table_count > db_count) {
		sprintf(update_query, update_cmd, val->count, val->latest, fingerprint);
		printf("%s\n", update_query);

		res = PQexec(db_conn, update_query);
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			fprintf(stderr, "postgres: %s\n", PQerrorMessage(db_conn));
			return;
		}
		PQclear(res);
	} else {
		printf("no update required for %s\n", fingerprint);
	}
}

void update_db(PGconn *db_conn, GHashTable *hash_table)
{
	/* iterate through hash table, updating database as required */
	g_hash_table_foreach(hash_table, update_record, (gpointer) db_conn);
}
