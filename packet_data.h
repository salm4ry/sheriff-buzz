#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
/* #include <math.h> */

#include <bpf/libbpf.h>
#include <glib-2.0/glib.h>
#include <postgresql/libpq-fe.h>

#include <sys/queue.h>

#include "parse_headers.h"

/* maximum fingerprint string length */
#define MAX_FINGERPRINT 13
#define MAX_QUERY 512
#define MAX_IP 16

#define MAX_DB_TASKS 20

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

struct db_task_list;

/**
 * Database work (linked list entry)
 *
 * fingerprint: hash table key
 * alert type: type of alert to be logged
 * key: key data from hash table fingerprint
 * value: hash table value
 */
struct db_task {
	char fingerprint[MAX_FINGERPRINT];
	int alert_type;
	struct key *key;
	struct value *value;
	LIST_ENTRY(db_task) entries;
};

LIST_HEAD(db_task_list, db_task);

/**
 * Arguments for database worker thread
 *
 * head: head of task linked list
 * db_conn: database connection
 */
struct thread_args {
	struct db_task_list *head;
	pthread_mutex_t *lock;
	PGconn *db_conn;
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
	err = (PQresultStatus(db_res) != PGRES_COMMAND_OK);

	if (err) {
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

int list_size(struct db_task_list *head)
{
	struct db_task *current = NULL;
	/* NOTE can use LIST_EMPTY() to check if list is empty */
	int size = 0;

	LIST_FOREACH(current, head, entries)
		size++;

	return size;
}

int list_full(struct db_task_list *head)
{
	return list_size(head) >= MAX_DB_TASKS;
}

/* log_alert(PGconn *db_conn, char *fingerprint, int alert_type, struct key *key, struct value *value) */
int add_work(struct db_task_list *task_list_head, pthread_mutex_t *lock,
			 char *fingerprint, int alert_type, struct key *key, struct value *value)
{
	struct db_task *new_task;

	if (list_full(task_list_head)) {
		return 1;
	}

	new_task = malloc(sizeof(struct db_task));

	strncpy(new_task->fingerprint, fingerprint, MAX_FINGERPRINT);
	new_task->alert_type = alert_type;
	new_task->key = key;
	new_task->value = value;

	pthread_mutex_lock(lock);
	LIST_INSERT_HEAD(task_list_head, new_task, entries);
	pthread_mutex_unlock(lock);

	return 0;
}

void thread_work(void *args)
{
	struct thread_args *ctx = args;
	PGconn *db_conn = ctx->db_conn;
	struct db_task_list *head = ctx->head;
	pthread_mutex_t *lock = ctx->lock;

	struct db_task *current, *next;

	/* loop forever, waiting for work from task list */
	while (true) {
		pthread_mutex_lock(lock);
		current = LIST_FIRST(head);
		pthread_mutex_unlock(lock);

		while (current) {
			log_alert(db_conn,
					current->fingerprint,
					current->alert_type,
					current->key,
					current->value);

			pthread_mutex_lock(lock);
			next = LIST_NEXT(current, entries);
			LIST_REMOVE(current, entries);
			free(current);
			pthread_mutex_unlock(lock);

			current = next;
		}
	}
}
