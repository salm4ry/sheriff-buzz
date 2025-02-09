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

#include <pthread.h>
#include <sys/queue.h>

#include "log.h"
#include "pr.h"
#include "alert_types.h"
#include "parse_headers.h"

/* maximum fingerprint string length */
#define MAX_FINGERPRINT 13
#define MAX_QUERY 512
#define MAX_IP 16
#define MAX_IP_HEX 8
#define MAX_PORT_RANGE 12

#define MAX_DB_TASKS 20

/**
 * Hash table key
 *
 * src_ip: source IP address
 */
struct key {
	in_addr_t src_ip;
};

/**
 * Hash table value
 *
 * - first: timestamp of first packet received
 * - latest: timestamp of latest packet received
 * - total_port_count: total number of ports IP has sent packets to
 * - total_packet_count: total number of packets IP has sent 
 *   	(used in database logging)
 * - alert_count: number of alerts triggered by IP
 * - ports: per-port packet counts
 */
struct value {
	time_t first;
	time_t latest;
	int total_port_count;
	int total_packet_count;
	int alert_count;
	unsigned long ports[NUM_PORTS];
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
	int dst_port;
	struct key key;
	struct value value;
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
	pthread_mutex_t *task_queue_lock;
	pthread_cond_t *task_queue_cond;
	pthread_mutex_t *db_lock;
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

static int min_port(unsigned long *ports_scanned)
{
	for (int i = 0; i < NUM_PORTS; i++) {
		if (ports_scanned[i] != 0) {
			return i;
		}
	}

	/* no ports scanned */
	return -1;
}

static int max_port(unsigned long *ports_scanned)
{
	for (int i = NUM_PORTS - 1; i >= 0; i--) {
		if (ports_scanned[i] != 0) {
			return i;
		}
	}

	/* no ports scanned */
	return -1;
}

/*
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
*/

/* create string fingerprint from key struct */
/*
void get_fingerprint(struct key *key, char *buf)
{
	// zero-padded so fingerprints are always of length MAX_FINGERPRINT
	snprintf(buf, MAX_FINGERPRINT, "%08x%04x", key->src_ip, key->dst_port);
}
*/

/* generate port-based fingerprints for a given source IP and flag combination */
/*
char **ip_fingerprint(in_addr_t src_ip)
{
	char **fingerprint = malloc(NUM_PORTS * sizeof(char *));
	if (!fingerprint) {
		pr_err("memory allocation failed: %s\n", strerror(errno));
		exit(1);
	}


	struct key current_key;
	current_key.src_ip = src_ip;

	for (int i = 0; i < NUM_PORTS; i++) {
		current_key.dst_port = i;
		fingerprint[i] = malloc((MAX_FINGERPRINT+1) * sizeof(char));
		if (!fingerprint[i]) {
			pr_err("memory allocation failed: %s\n", strerror(errno));
			exit(1);
		}

		get_fingerprint(&current_key, fingerprint[i]);
	}

	return fingerprint;
}
*/

/* free per-port IP fingerprints */
void free_ip_fingerprint(char **fingerprint)
{
	for (int i = 0; i < NUM_PORTS; i++) {
		free(fingerprint[i]);
	}
	free(fingerprint);
}

void update_entry_count(gpointer key, gpointer value, gpointer user_data)
{
    int *count = (int*) user_data;
     *count += 1;
 }

/* get number of entries in hash table */
int count_entries(GHashTable *table)
{
    int count = 0;
    g_hash_table_foreach(table, &update_entry_count, &count);

    return count;
}

/* get list of ports a given IP (and flag combination) has sent packets to */
/*
void ports_scanned(GHashTable *packet_table, in_addr_t src_ip, bool *ports_scanned)
{
	char **fingerprint = ip_fingerprint(src_ip);
	gboolean res;

	for (int i = 0; i < NUM_PORTS; i++) {
		res = g_hash_table_contains(packet_table, (gconstpointer) fingerprint[i]);
		ports_scanned[i] = res;
	}

	free_ip_fingerprint(fingerprint);
}
*/

/* get information about packets a given IP has sent
 *
 * struct port_info contains information about ports the source IP has sent
 * packets to and the total number of packets it has sent
 */
/*
void port_info(GHashTable *packet_table, in_addr_t src_ip, struct port_info *info)
{
	char **fingerprint = ip_fingerprint(src_ip);
	struct value *res;

	info->total_packet_count = 0;

	for (int i = 0; i < NUM_PORTS; i++) {
		res = g_hash_table_lookup(packet_table, (gconstpointer) fingerprint[i]);

		if (res != NULL) {
			info->ports_scanned[i] = true;
			info->total_packet_count++;
		} else {
			info->ports_scanned[i] = false;
		}
	}

	free_ip_fingerprint(fingerprint);
}
*/

/* check if hash table entry is related to a target IP
 *
 * key = hash table key
 * value = hash table value (unused, required for foreach_remove)
 * user_data = IP portion of fingerprint to compare to
 */
gboolean fingerprint_ip_equal(gpointer key, gpointer value, gpointer user_data)
{
    /* check if fingerprint is in IP fingerpint list */
    char *key_fingerprint = (char *) key;
    char *target_fingerprint = (char *) user_data;

	return (strncmp(key_fingerprint, target_fingerprint, MAX_IP_HEX) == 0);
}

/* delete all hash table entries related to a given IP
 *
 * ip = target IP to delete entries about
 * packet_table = packet information hash table
 */
void delete_ip_entries(in_addr_t ip, GHashTable *packet_table)
{
	char ip_fingerprint[MAX_IP_HEX+1];
	snprintf(ip_fingerprint, MAX_IP_HEX+1, "%08x", ip);

    g_hash_table_foreach_remove(packet_table, &fingerprint_ip_equal, ip_fingerprint);
}

int get_alert_count(PGconn *conn, pthread_mutex_t *db_lock, char *src_addr)
{
	int err, alert_count = 0, query_size;
	PGresult *db_res;
	char *cmd, *query;

	/* set up query components */
	cmd = "SELECT count(id) FROM log WHERE src_ip = '%s'";

	/* build query */
	query_size = strlen(cmd) + MAX_IP;
	query = malloc(query_size * sizeof(char));
	if (!query) {
		pr_err("memory allocation failed: %s\n", strerror(errno));
		exit(1);
	}


	snprintf(query, query_size, cmd, src_addr);

#ifdef DEBUG
	log_debug("%s\n", query);
#endif

	pthread_mutex_lock(db_lock);
	db_res = PQexec(conn, query);
	pthread_mutex_unlock(db_lock);

	err = (PQresultStatus(db_res) != PGRES_TUPLES_OK);
	if (err) {
		log_error("postgres: %s\n", PQerrorMessage(conn));
	} else {
#ifdef DEBUG
		log_debug("%s alert count = %s\n", src_addr, PQgetvalue(db_res, 0, 0));
#endif
		alert_count = atoi(PQgetvalue(db_res, 0, 0));
	}

	PQclear(db_res);


	return alert_count;
}

/* log alert to database, replacing old record if necessary */
int db_alert(PGconn *conn, pthread_mutex_t *db_lock, int alert_type,
		struct key *key, struct value *value, int dst_port)
{
	PGresult *db_res;
	int err;
	char query[MAX_QUERY];
	char ip_str[MAX_IP];
	char *cmd;

	in_addr_t src_ip = ntohl(key->src_ip);
	inet_ntop(AF_INET, &src_ip, ip_str, MAX_IP);

	switch (alert_type) {
		case PORT_SCAN:
			/* port-based alert
			 *
			 * destination port is a string colon-delimited range
			 * packet_count = total packet count from src_ip
			 */
			cmd = "INSERT INTO log (dst_port, alert_type, src_ip, port_count, packet_count, first, latest) "
				  "VALUES ('%s', %d, '%s', %d, %d, to_timestamp(%ld), to_timestamp(%ld)) "
				  "ON CONFLICT (src_ip, alert_type) "
				  "DO UPDATE SET port_count=%d, dst_port='%s', latest=to_timestamp(%ld) "
				  "WHERE %d > log.packet_count AND to_timestamp(%ld) > log.latest";

			char port_range[MAX_PORT_RANGE];
			int min = min_port(value->ports);
			int max = max_port(value->ports);
			int port_count = value->total_port_count;

			snprintf(port_range, MAX_PORT_RANGE, "%d:%d", min, max);
			snprintf(query, MAX_QUERY, cmd, port_range, alert_type, ip_str,
					port_count, value->total_packet_count, value->first, value->latest,
					/* fields to update */
					port_count, port_range, value->latest,
					/* only update if packet count and timestamp are newer */
					value->total_packet_count, value->latest);
			break;
		default:
			/* flag-based scan
			 *
			 * destination is a single port
			 * packet_count = total packet count from src_ip to dst_port
			 */
			cmd = "INSERT INTO log (dst_port, alert_type, src_ip, packet_count, first, latest) "
		   		  "VALUES ('%d', %d, '%s', %d, to_timestamp(%ld), to_timestamp(%ld)) "
				  "ON CONFLICT (src_ip, alert_type) "
				  "DO UPDATE SET packet_count=%d, latest=to_timestamp(%ld) "
				  "WHERE %d > log.packet_count AND to_timestamp(%ld) > log.latest";

			snprintf(query, MAX_QUERY, cmd, dst_port, alert_type,
					ip_str, value->total_packet_count, value->first, value->latest,
					/* fields to update */
					value->total_packet_count, value->latest,
					/* only update if packet count and timestamp are newer */
					value->total_packet_count, value->latest); 
					break;
	}


#ifdef DEBUG
	log_debug("%s\n", query);
#endif

	pthread_mutex_lock(db_lock);
	db_res = PQexec(conn, query);
	pthread_mutex_unlock(db_lock);

	err = (PQresultStatus(db_res) != PGRES_COMMAND_OK);
	if (err) {
		log_error("postgres: %s\n", PQerrorMessage(conn));
	}

	PQclear(db_res);

	return err;
}

/*
int db_alert(PGconn *conn, pthread_mutex_t *db_lock,
		char *fingerprint, int alert_type, struct key *key, struct value *value,
		struct port_info *info)
*/
int db_flagged(PGconn *conn, pthread_mutex_t *db_lock,
        struct key *key, struct value *value)
{
    int err = 0;
	PGresult *db_res;
	char query[MAX_QUERY];
    char *cmd;
	char ip_str[MAX_IP];

	in_addr_t src_ip = ntohl(key->src_ip);
	inet_ntop(AF_INET, &src_ip, ip_str, MAX_IP);

    cmd = "INSERT INTO flagged (src_ip, time) VALUES ('%s', to_timestamp(%ld))";
    snprintf(query, MAX_QUERY, cmd, ip_str, value->latest);

    pthread_mutex_lock(db_lock);
    db_res = PQexec(conn, query);
    pthread_mutex_unlock(db_lock);

    err = (PQresultStatus(db_res) != PGRES_COMMAND_OK);
    if (err) {
        log_error("postgres: %s\n", PQerrorMessage(conn));
    }

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
		pthread_cond_t *cond, int alert_type,
		struct key *key, struct value *value, int dst_port)
{
	struct db_task *new_task;

	if (queue_full(task_queue_head)) {
		return 1;
	}

	new_task = malloc(sizeof(struct db_task));
	if (!new_task) {
		pr_err("memory allocation failed: %s\n", strerror(errno));
		exit(1);
	}

	switch (alert_type) {
		case PORT_SCAN:
			/* no destination port required */
			break;
		case 0:
			/* no alert type set */
			break;
		default:
			/* flag-based alerts have destination port */
			new_task->dst_port = dst_port;
	}

	new_task->alert_type = alert_type;
	memcpy(&new_task->key, key, sizeof(struct key));
	memcpy(&new_task->value, value, sizeof(struct value));

	pthread_mutex_lock(lock);
	TAILQ_INSERT_TAIL(task_queue_head, new_task, entries);
	pthread_cond_signal(cond);
	pthread_mutex_unlock(lock);

	return 0;
}

void db_thread_work(void *args)
{
	struct db_thread_args *ctx = args;
	PGconn *db_conn = ctx->db_conn;
	struct db_task_queue *head = ctx->head;
	pthread_mutex_t *task_queue_lock = ctx->task_queue_lock;
	pthread_cond_t *task_queue_cond = ctx->task_queue_cond;
	pthread_mutex_t *db_lock = ctx->db_lock;

	struct db_task *current;

	/* loop forever, waiting for work from task list */
	while (true) {
		pthread_mutex_lock(task_queue_lock);

		while (TAILQ_EMPTY(head)) {
			pthread_cond_wait(task_queue_cond, task_queue_lock);
		}

		/* grab new entry and remove from queue */
		current = TAILQ_FIRST(head);
		TAILQ_REMOVE(head, current, entries);
		pthread_mutex_unlock(task_queue_lock);

		if (current->alert_type) {
			/* write alert to database */
			db_alert(db_conn, db_lock,
					current->alert_type,
					&current->key,
					&current->value,
					current->dst_port);
		} else {
			/* write flagged IP to database */
			db_flagged(db_conn, db_lock, &current->key, &current->value);
		}

		free(current);
	}
}
