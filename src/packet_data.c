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

#include "include/packet_data.h"
#include "include/log.h"

/* maximum fingerprint string length */
#define MAX_FINGERPRINT 13
#define MAX_QUERY 512
#define MAX_IP 16
#define MAX_IP_HEX 8
#define MAX_PORT_RANGE 12

#define MAX_DB_TASKS 20

struct db_task_queue;

void min_max_port(gpointer key, gpointer value, gpointer user_data)
{
	struct port_range *range = (struct port_range *) user_data;
	int *port = (int *) key;

	/* update min and max according to key */
	if (*port > range->max) {
		range->max = *port;
	}

	if (*port < range->min) {
		range->min = *port;
	}
}

/* get min and max port from port count hash table */
struct port_range *lookup_port_range(GHashTable *port_counts)
{
	struct port_range *res = malloc(sizeof(struct port_range));
	if (!res) {
		perror("memory allocation failed");
		exit(errno);
	}

	res->min = 65535;
	res->max = 0;

	g_hash_table_foreach(port_counts, &min_max_port, (gpointer) res);

	return res;
}

void destroy_port_table(gpointer key, gpointer value, gpointer user_data)
{
	struct value *val = (struct value *) value;
	g_hash_table_destroy(val->ports);
}


/* destroy all IP entries' port hash tables */
void port_table_cleanup(GHashTable *packet_table)
{
	g_hash_table_foreach(packet_table, &destroy_port_table, NULL);
}

/**
 * Helper to update hash table entry count
 *
 * - key: hash table key
 * - value: hash table value
 * - user_data: count vaule to update
 */
/* TODO double check this works in small example */
void update_entry_count(gpointer key, gpointer value, gpointer user_data)
{
	*((int*) user_data) = *((int*) user_data) + 1;
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

/* initialise hash table entry either based on existing entry or new */
void init_entry(GHashTable *table, struct key *key, struct value *val, int dst_port)
{
	gpointer res = g_hash_table_lookup(table, (gconstpointer) &key->src_ip);
	if (res) {
		/* entry already exists: update count and timestamp */
		struct value *current_val = (struct value*) res;
		gpointer port_count_res;
		unsigned long new_port_count;

		val->first = current_val->first;
		val->latest = time(NULL);
		val->total_packet_count = current_val->total_packet_count + 1;
		val->total_port_count = current_val->total_port_count;
		val->alert_count = current_val->alert_count;

		/* use existing per-port count hash table */
		val->ports = current_val->ports;

		/* look up current port's packet count */
		port_count_res = g_hash_table_lookup(val->ports, (gconstpointer) &dst_port);
		if (port_count_res) {
			/* increment count */
			new_port_count = (unsigned long) port_count_res + 1;
		} else {
			/* no packets sent to this port before: set count to 1 and
			 * increment total port count */
			new_port_count = 1;
			val->total_port_count++;
		}

		/* update current port's packet count */
		g_hash_table_insert(val->ports,
			g_memdup2((gconstpointer) &dst_port, sizeof(int)),
			g_memdup2((gconstpointer) &new_port_count, sizeof(unsigned long)));
	} else {
		/* set up new entry */
		val->first = time(NULL);
		val->latest = val->first;

		/* set up total packet, port, and alert counts */
		val->total_port_count = 1;
		val->total_packet_count = 1;
		val->alert_count = 0;

		/* create new per-port count hash table */
		val->ports = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, g_free);
	}
}

void update_entry(GHashTable *table, struct key *key, struct value *val,
		bool flagged)
{
	if (flagged) {
		/* flagged: destroy IP's port hash table and remove IP entry from
		 * packet hash table */
          g_hash_table_destroy(val->ports);
          g_hash_table_remove(table, (gconstpointer)&key->src_ip);
	} else {
		/* insert/update entry */
		g_hash_table_replace(table,
				g_memdup2((gconstpointer) &key->src_ip, sizeof(in_addr_t)),
				g_memdup2((gconstpointer) val, sizeof(struct value)));
	}
}

/**
 *
 * Log alert to database (upsert)
 *
 * - conn: database connection
 * - alert_type: type of alert (from alert_type enum)
 * - key: hash table key
 * - value: hash table value
 * - dst_port: alert destination port (optional- flag-based alerts only)
 *
 *
 * Return 0 on success, non-zero value on error
 */
int db_write_scan_alert(PGconn *conn, int alert_type,
		struct key *key, struct value *value, struct port_range *range, 
		int dst_port, FILE *LOG)
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
			cmd = "INSERT INTO scan_alerts (dst_port, alert_type, src_ip, port_count, packet_count, first, latest) "
				  "VALUES ('%s', %d, '%s', %d, %d, to_timestamp(%ld), to_timestamp(%ld)) "
				  "ON CONFLICT (src_ip, dst_port, alert_type) "
				  "DO UPDATE SET port_count=%d, dst_port='%s', latest=to_timestamp(%ld) "
				  "WHERE %d > scan_alerts.packet_count AND to_timestamp(%ld) > scan_alerts.latest";

			char port_range[MAX_PORT_RANGE];
			int port_count = value->total_port_count;

			snprintf(port_range, MAX_PORT_RANGE, "%d:%d", range->min, range->max);
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
			cmd = "INSERT INTO scan_alerts (dst_port, alert_type, src_ip, packet_count, first, latest) "
		   		  "VALUES ('%d', %d, '%s', %d, to_timestamp(%ld), to_timestamp(%ld)) "
				  "ON CONFLICT (src_ip, dst_port, alert_type) "
				  "DO UPDATE SET packet_count=%d, latest=to_timestamp(%ld) "
				  "WHERE %d > scan_alerts.packet_count AND to_timestamp(%ld) > scan_alerts.latest";

			snprintf(query, MAX_QUERY, cmd, dst_port, alert_type,
					ip_str, value->total_packet_count, value->first, value->latest,
					/* fields to update */
					value->total_packet_count, value->latest,
					/* only update if packet count and timestamp are newer */
					value->total_packet_count, value->latest); 
					break;
	}


	log_debug(LOG, "%s\n", query);

	db_res = PQexec(conn, query);

	err = (PQresultStatus(db_res) != PGRES_COMMAND_OK);
	if (err) {
		log_error(LOG, "postgres: %s\n", PQerrorMessage(conn));
	}

	PQclear(db_res);

	return err;
}

/**
 * Log flagged IP address to database
 *
 * - conn: database connection
 * - key: hash table key
 * - value: hash table value
 *
 * Return 0 on success, non-zero on error
 */
int db_write_blocked_ip(PGconn *conn, struct key *key, struct value *value,
		FILE *LOG)
{
    int err = 0;
	PGresult *db_res;
	char query[MAX_QUERY];
    char *cmd;
	char ip_str[MAX_IP];

	in_addr_t src_ip = ntohl(key->src_ip);
	inet_ntop(AF_INET, &src_ip, ip_str, MAX_IP);

    cmd = "INSERT INTO blocked_ips (src_ip, time) VALUES ('%s', to_timestamp(%ld))";
    snprintf(query, MAX_QUERY, cmd, ip_str, value->latest);

    db_res = PQexec(conn, query);

    err = (PQresultStatus(db_res) != PGRES_COMMAND_OK);
    if (err) {
        log_error(LOG, "postgres: %s\n", PQerrorMessage(conn));
    }

	PQclear(db_res);

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
PGconn *connect_db(char *user, char *dbname, FILE *LOG)
{
	char query[MAX_QUERY];

	snprintf(query, MAX_QUERY, "user=%s dbname=%s", user, dbname);
	PGconn *db = PQconnectdb(query);
	if (PQstatus(db) != CONNECTION_OK) {
		log_error(LOG, "connection to database failed: %s\n", PQerrorMessage(db));

		/* clean up connection */
		PQfinish(db);

		return NULL;
	}

	return db;
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
		struct key *key, struct value *value, int dst_port,
		FILE *LOG)
{
	struct db_task *new_task;
	struct port_range *range;

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
			/* port-based alert: min and max ports */
			range = lookup_port_range(value->ports);
			new_task->range = *range;
			free(range);
			break;
		case 0:
			/* no alert type set */
			break;
		default:
			/* flag-based alert: destination port */
			new_task->dst_port = dst_port;
	}

	new_task->alert_type = alert_type;
	memcpy(&new_task->key, key, sizeof(struct key));

	/* copy parts of hash table key required for database write */
	new_task->value.first = value->first;
	new_task->value.latest = value->latest;
	new_task->value.total_packet_count = value->total_packet_count;
	new_task->value.total_port_count = value->total_port_count;
	new_task->log_file = LOG;

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
			db_write_scan_alert(db_conn,
					current->alert_type,
					&current->key,
					&current->value,
					&current->range,
					current->dst_port,
					current->log_file);
		} else {
			/* write flagged IP to database */
			db_write_blocked_ip(db_conn, &current->key, &current->value, current->log_file);
		}

		free(current);
	}
}
