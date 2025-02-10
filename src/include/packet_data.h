#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

/* for ULONG_MAX
#include <limits.h>
*/

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

struct packet_count {
    unsigned long val;
    /* carry when val reaches ULONG_MAX (starts at 0)
     * TODO: how big should carry be? */
    int carry;
};

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
 * - alert_type: type of alert to be logged
 * - dst_port: alert destination port (optional)
 * - key: hash table key alert is concerned with
 * - value: hash table value alert is concerned with
 * - entries: database workqueue structure
 */
struct db_task {
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
 * - head: head of task queue
 * - task_queue_lock: database task queue lock
 * - task_queue_cond: database tack queue condition
 * - db_lock: database lock (TODO remove)
 * - db_conn: database connection
 */
struct db_thread_args {
	struct db_task_queue *head;
	pthread_mutex_t *task_queue_lock;
	pthread_cond_t *task_queue_cond;
	pthread_mutex_t *db_lock;
	PGconn *db_conn;
};

/**
 * Get the minimum port number used
 *
 * ports: per-port packet count array
 *
 * Return -1 on error
 */
static int min_port(unsigned long *ports)
{
	for (int i = 0; i < NUM_PORTS; i++) {
		if (ports[i] != 0) {
			return i;
		}
	}

	/* error: no ports scanned */
	return -1;
}

/**
 * Get the maximum port number used
 *
 * - ports: per-port packet count array
 *
 * Return -1 on error
 */
static int max_port(unsigned long *ports)
{
	for (int i = NUM_PORTS - 1; i >= 0; i--) {
		if (ports[i] != 0) {
			return i;
		}
	}

	/* no ports scanned */
	return -1;
}


/**
 * Helper to update hash table entry count
 *
 * - key: hash table key
 * - value: hash table value
 * - user_data: count vaule to update
 */
void update_entry_count(gpointer key, gpointer value, gpointer user_data)
{
    int *count = (int*) user_data;
     *count += 1;
 }

/**
 * Get number of entries in a GHashTable
 *
 * table: hash table to count entries of
 *
 * Walks the hash table, incrementing the final count value for each entry
 */
int count_entries(GHashTable *table)
{
    int count = 0;
    g_hash_table_foreach(table, &update_entry_count, &count);

    return count;
}

/**
 *
 * Log alert to database (upsert)
 *
 * - conn: database connection
 * - db_lock: database lock (TODO remove)
 * - alert_type: type of alert (from alert_type enum)
 * - key: hash table key
 * - value: hash table value
 * - dst_port: alert destination port (optional- flag-based alerts only)
 *
 *
 * Return 0 on success, non-zero value on error
 */
int db_alert(PGconn *conn, pthread_mutex_t *db_lock, int alert_type,
		struct key *key, struct value *value, int dst_port)
{
	PGresult *db_res;
	int err = 0;
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

/**
 * Log flagged IP address to database
 *
 * - conn: database connection
 * - db_lock: database lock (TODO remove)
 * - key: hash table key
 * - value: hash table value
 *
 * Return 0 on success, non-zero on error
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

/**
 * Connect to PostgreSQL database with peer authentication (postgres username =
 * system username)
 *
 * - user: username
 * - dbname: database name
 *
 * Return the database connection object on success, NULL on error
 */
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

/**
 * Calculate the number of entries in a database task queue (tailq)
 *
 * head: head of queue
 */
int queue_size(struct db_task_queue *head)
{
	struct db_task *current = NULL;
	/* NOTE can use LIST_EMPTY() to check if list is empty */
	int size = 0;

	TAILQ_FOREACH(current, head, entries)
		size++;

	return size;
}

/**
 * Determine whether a database task queue is full
 *
 * head: head of queue
 *
 * Return 1 if full, 0 otherwise
 */
int queue_full(struct db_task_queue *head)
{
	return queue_size(head) >= MAX_DB_TASKS;
}

/**
 * Queue database work
 *
 * - task_queue_head: head of database work queue
 * - lock: task queue lock
 * - cond: task queue condition
 * - alert_type: type of alert
 * - key: hash table key
 * - value: hash table value
 * - dst_port: destination port (optional- used for flag-based alerts)
 *
 * Return 0 on success, 1 on error (queue full)
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

/**
 * Work for database thread
 *
 * args = struct db_thread_args passed to the thread on creation
 *
 * Wait for work from the task queue and carry it out as it arrives
 */
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
