#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
/* #include <math.h> */

#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <glib-2.0/glib.h>
#include <postgresql/libpq-fe.h>

#include <sys/queue.h>

#include "log.h"
#include "alert_types.h"
#include "parse_headers.h"

/* maximum fingerprint string length */
#define MAX_FINGERPRINT 13
#define MAX_QUERY 512
#define MAX_IP 16
#define MAX_PORT_RANGE 12

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

struct port_info {
	bool ports_scanned[65536];
	int total_packet_count;
};

struct db_task_queue;
FILE *LOG;

/**
 * Database work queue entry
 *
 * fingerprint: hash table key
 * alert type: type of alert to be logged
 * key: key data from hash table fingerprint
 * value: hash table value
 */
struct db_task {
	char fingerprint[MAX_FINGERPRINT];
	int alert_type;
	struct key key;
	struct value value;
	struct port_info info;
	TAILQ_ENTRY(db_task) entries;
};

TAILQ_HEAD(db_task_queue, db_task);

/**
 * Arguments for database worker thread
 *
 * head: head of task linked list
 * db_conn: database connection
 */
struct db_thread_args {
	struct db_task_queue *head;
	pthread_mutex_t *lock;
	PGconn *db_conn;
};

/**
 * Detection work queue entry
 *
 * tcph: current packet TCP headers
 * ports: list of ports packet source IP has sent packets to
 * TODO add more if handling other protocols
 *
 */
struct detection_task {
	struct tcphdr tcph;
	bool ports[NUM_PORTS];
};

static int min_port(bool *ports_scanned)
{
	for (int i = 0; i < NUM_PORTS; i++) {
		if (ports_scanned[i]) {
			return i;
		}
	}

	/* no ports scanned */
	return -1;
}

static int max_port(bool *ports_scanned)
{
	for (int i = NUM_PORTS - 1; i >= 0; i--) {
		if (ports_scanned[i]) {
			return i;
		}
	}

	/* no ports scanned */
	return -1;
}

static int count_ports_scanned(bool *ports_scanned)
{
	int port_count = 0;

	for (int i = 0; i < NUM_PORTS; i++) {
		if (ports_scanned[i]) {
			port_count++;
		}
	}

	return port_count;
}

/* create string fingerprint from key struct */
void get_fingerprint(struct key *key, char *buf)
{
	/* zero-padded so fingerprints are always of length MAX_FINGERPRINT */
	snprintf(buf, MAX_FINGERPRINT, "%08lx%04x", key->src_ip, key->dst_port);
}

/* generate port-based fingerprints for a given source IP and flag combination */
char **ip_fingerprint(long src_ip)
{
	char **fingerprint = malloc(NUM_PORTS * sizeof(char *));
	struct key current_key;
	current_key.src_ip = src_ip;

	for (int i = 0; i < NUM_PORTS; i++) {
		current_key.dst_port = i;
		fingerprint[i] = malloc((MAX_FINGERPRINT+1) * sizeof(char));
		get_fingerprint(&current_key, fingerprint[i]);
	}

	return fingerprint;
}

/* free per-port IP fingerprints */
void free_ip_fingerprint(char **fingerprint)
{
	for (int i = 0; i < NUM_PORTS; i++) {
		free(fingerprint[i]);
	}
	free(fingerprint);
}

int get_alert_count(PGconn *conn, char *src_addr)
{
	int err, alert_count = 0, query_size;
	PGresult *db_res;
	char *cmd, *query;

	/* set up query components */
	cmd = "SELECT count(id) FROM log WHERE src_ip = '%s'";

	/* build query */
	query_size = strlen(cmd) + MAX_IP;
	query = malloc(query_size * sizeof(char));
	snprintf(query, query_size, cmd, src_addr);

#ifdef DEBUG
	log_debug("%s\n", query);
#endif

	db_res = PQexec(conn, query);
	err = (PQresultStatus(db_res) != PGRES_TUPLES_OK);
	if (err) {
		log_error("postgres: %s\n", PQerrorMessage(conn));
	} else {
#ifdef DEBUG
		log_debug("%s alert count = %s\n", src_addr, PQgetvalue(db_res, 0, 0));
#endif
		/* TODO convert to int and return */
	}

	PQclear(db_res);


	return alert_count;
}

/* log alert to database, replacing old record if necessary */
int db_alert(PGconn *conn, char *fingerprint, int alert_type,
		struct key *key, struct value *value,
		struct port_info *info)
{
	PGresult *db_res;
	int err;
	char query[MAX_QUERY];
	char ip_str[MAX_IP];
	char *cmd;

	long src_ip = ntohl(key->src_ip);
	inet_ntop(AF_INET, &src_ip, ip_str, MAX_IP);

	switch (alert_type) {
		case BASIC_SCAN:
			/* port-based alert
			 *
			 * destination port is a string colon-delimited range
			 * packet_count = total packet count from src_ip
			 */
			cmd = "INSERT INTO log (dst_port, alert_type, src_ip, port_count, first, latest) "
				  "VALUES ('%s', %d, '%s', %d, to_timestamp(%ld), to_timestamp(%ld)) "
				  "ON CONFLICT (src_ip, alert_type) WHERE fingerprint IS NULL "
				  "DO UPDATE SET port_count=%d, dst_port='%s', latest=to_timestamp(%ld) "
				  "WHERE %d > log.port_count AND to_timestamp(%ld) > log.latest";

			char port_range[MAX_PORT_RANGE];
			int min = min_port(info->ports_scanned);
			int max = max_port(info->ports_scanned);
			int port_count = count_ports_scanned(info->ports_scanned);

			snprintf(port_range, MAX_PORT_RANGE, "%d:%d", min, max);
			snprintf(query, MAX_QUERY, cmd, port_range, alert_type, ip_str,
					port_count, value->first, value->latest, /* fields to update */
					port_count, port_range, value->latest,
					port_count, value->latest);
			break;
		default:
			/* flag-based scan
			 *
			 * destination is a single port
			 * packet_count = total packet count from src_ip to dst_port
			 */
			cmd = "INSERT INTO log (fingerprint, dst_port, alert_type, src_ip, packet_count, first, latest) "
		   		  "VALUES ('%s', '%d', %d, '%s', %d, to_timestamp(%ld), to_timestamp(%ld)) "
				  "ON CONFLICT (src_ip, fingerprint, alert_type) WHERE fingerprint IS NOT NULL "
				  "DO UPDATE SET packet_count=%d, latest=to_timestamp(%ld) "
				  "WHERE %d > log.packet_count AND to_timestamp(%ld) > log.latest";

			snprintf(query, MAX_QUERY, cmd, fingerprint, key->dst_port, alert_type,
					ip_str, value->count, value->first, value->latest,
					value->count, value->latest,  /* fields to update */
					value->count, value->latest); /* only update if packet count/timestamp are same/newer */
					break;
	}


#ifdef DEBUG
	log_debug("%s\n", query);
#endif

	db_res = PQexec(conn, query);
	err = (PQresultStatus(db_res) != PGRES_COMMAND_OK);
	if (err) {
		log_error("postgres: %s\n", PQerrorMessage(conn));
	}

	PQclear(db_res);

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
		log_error("connection to database failed: %s\n", PQerrorMessage(conn));

		PQfinish(conn);
		/* return NULL on error */
		return NULL;
	}

	return conn;
}

int queue_size(struct db_task_queue *head)
{
	struct db_task *current = NULL;
	/* NOTE can use LIST_EMPTY() to check if list is empty */
	int size = 0;

	TAILQ_FOREACH(current, head, entries)
		size++;

	return size;
}

int queue_full(struct db_task_queue *head)
{
	return queue_size(head) >= MAX_DB_TASKS;
}

/**
 * Queue database work
 *
 * provide data such that the database worker can carry out:
 *
 * db_alert(PGconn *db_conn, char *fingerprint, int alert_type, 
 * 		struct key *key, struct value *value) 
 */
int queue_work(struct db_task_queue *task_queue_head, pthread_mutex_t *lock,
			 char *fingerprint, int alert_type, struct key *key, struct value *value,
			 struct port_info *info)
{
	struct db_task *new_task;

	if (queue_full(task_queue_head)) {
		return 1;
	}

	new_task = malloc(sizeof(struct db_task));

	if (alert_type == BASIC_SCAN) {
		/* basic scan has port_info argument */
		memcpy(&new_task->info, info, sizeof(struct port_info));
	} else {
		/* flag-based scans have fingerprint argument */
		strncpy(new_task->fingerprint, fingerprint, MAX_FINGERPRINT);
	}

	new_task->alert_type = alert_type;
	memcpy(&new_task->key, key, sizeof(struct key));
	memcpy(&new_task->value, value, sizeof(struct value));

	pthread_mutex_lock(lock);
	TAILQ_INSERT_TAIL(task_queue_head, new_task, entries);
	pthread_mutex_unlock(lock);

	return 0;
}

void db_thread_work(void *args)
{
	struct db_thread_args *ctx = args;
	PGconn *db_conn = ctx->db_conn;
	struct db_task_queue *head = ctx->head;
	pthread_mutex_t *lock = ctx->lock;

	struct db_task *current, *next;

	/* loop forever, waiting for work from task list */
	while (true) {
		pthread_mutex_lock(lock);
		current = TAILQ_FIRST(head);
		pthread_mutex_unlock(lock);

		while (current) {
			db_alert(db_conn,
					current->fingerprint,
					current->alert_type,
					&current->key,
					&current->value,
					&current->info);

			pthread_mutex_lock(lock);
			next = TAILQ_NEXT(current, entries);
			TAILQ_REMOVE(head, current, entries);
			free(current);
			pthread_mutex_unlock(lock);

			current = next;
		}
	}
}
