/// @file

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
#include "include/bpf_common.h"

struct db_task_queue;

/**
 * @brief Update minimum and maximum port
 * @param key current hash table key
 * @param value current hash table value
 * @param user_data current minimum and maximum ports
 * @details g_hash_table_foreach() callback
 */
void min_max_port(gpointer key, gpointer value, gpointer user_data)
{
	int *port = (int *) key;
	struct port_lookup_ctx *ctx = (struct port_lookup_ctx *) user_data;
	struct port_range *range = ctx->range;

	/* update min and max according to key */

	switch (ctx->protocol) {
		case TCP_PNUM:
			if (*port > range->max_tcp)
				range->max_tcp = *port;
			if (*port < range->min_tcp)
				range->min_tcp = *port;
			break;
		case UDP_PNUM:
			if (*port > range->max_udp)
				range->max_udp = *port;
			if (*port < range->min_udp)
				range->min_udp = *port;
			break;
	}
}

/**
 * @brief Get TCP and UDP min and max ports present from port count hash tables
 * @param val value containing TCP and UDP port hash tables
 * @return port_range object containing TCP and UDP minimum and maximum ports
 */
struct port_range *lookup_port_range(struct value *val)
{
	struct port_range *res;
	struct port_lookup_ctx *ctx;

	ctx = malloc(sizeof(struct port_lookup_ctx));
	if (!ctx) {
		p_error("failed to allocate ctx");
		exit(errno);
	}

	res = malloc(sizeof(struct port_range));
	if (!res) {
		p_error("failed to allocate res");
		exit(errno);
	}

	res->min_tcp = INIT_MIN_PORT;
	res->max_tcp = INIT_MAX_PORT;

	res->min_udp = INIT_MIN_PORT;
	res->max_udp = INIT_MAX_PORT;

	/* get TCP min and max ports */
	ctx->range = res;
	ctx->protocol = TCP_PNUM;
	g_hash_table_foreach(val->tcp_ports, &min_max_port, (gpointer) ctx);

	/* get UDP min and max ports */
	ctx->protocol = UDP_PNUM;
	g_hash_table_foreach(val->udp_ports, &min_max_port, (gpointer) ctx);

	free(ctx);
	return res;
}

/**
 * @brief Format port range from minimum and maximum
 * @param buf output buffer
 * @param min minimum port
 * @param max maximum port
 * @details If min = max, output single port, otherwise output "min:max"
 */
void format_port_range(char *buf, int min, int max)
{
	if (min == INIT_MIN_PORT && max == INIT_MAX_PORT) {
		/* no ports found */
		snprintf(buf, MAX_PORT_RANGE, "");
	} else {
		if (min == max)
			snprintf(buf, MAX_PORT_RANGE, "%d", min);
		else
			snprintf(buf, MAX_PORT_RANGE, "%d:%d", min, max);
	}
}

/**
 * @brief Destroy port hash tables for a given packet entry
 * @param key packet hash table key
 * @param value packet hash table value
 * @param user_data context data passed from g_hash_table_foreach() (empty)
 * @details g_hash_table_foreach() callback
 */
void destroy_port_tables(gpointer key, gpointer value, gpointer user_data)
{
	struct value *val = (struct value *) value;
	g_hash_table_destroy(val->tcp_ports);
	g_hash_table_destroy(val->udp_ports);
}

/**
 * @brief Destroy all packet entries' port hash tables
 * @param packet_table hash table to iterate over
 */
void port_table_cleanup(GHashTable *packet_table)
{
	g_hash_table_foreach(packet_table, &destroy_port_tables, NULL);
}

/**
 * @brief Update hash table entry count (g_hash_table_foreach() callback)
 * @param key hash table key
 * @param value hash table value
 * @param user_data count value to update
 */
void update_entry_count(gpointer key, gpointer value, gpointer user_data)
{
	*((int*) user_data) = *((int*) user_data) + 1;
}

/**
 * @brief Get number of entries in a GHashTable
 * @param table hash table to count entries of
 * @return number of hash table entries
 * @details Walks the hash table, incrementing the final count value for each entry
 */
int count_entries(GHashTable *table)
{
	int count = 0;
	g_hash_table_foreach(table, &update_entry_count, &count);

    return count;
}

/**
 * @brief Get a given destination port's packet count
 * @param val packet hash table value containing port table to perform lookup on
 * @param dst_port destination port to look up
 * @param protocol protocol number (TCP/UDP) of destination port
 * @return lookup result on success, NULL on failure
 */
gpointer lookup_packet_count(struct value *val, int dst_port, int protocol)
{
	gpointer res = NULL;

	switch (protocol) {
		case TCP_PNUM:
			res = g_hash_table_lookup(val->tcp_ports, (gconstpointer) &dst_port);
			break;
		case UDP_PNUM:
			res = g_hash_table_lookup(val->udp_ports, (gconstpointer) &dst_port);
			break;
	}

	return res;
}

/**
 * @brief Update a destination port's packet count
 * @param val packet hash table value containing port table to update
 * @param dst_port destination port to update entry of
 * @param new_count new packet count
 * @param protocol protocol number (TCP/UDP) of destination port
 */
void update_packet_count(struct value *val, int dst_port, int new_count,
			 int protocol)
{
	switch (protocol) {
		case TCP_PNUM:
			g_hash_table_insert(val->tcp_ports,
				g_memdup2((gconstpointer) &dst_port, sizeof(int)),
				g_memdup2((gconstpointer) &new_count, sizeof(unsigned long)));
			break;
		case UDP_PNUM:
			g_hash_table_insert(val->udp_ports,
				g_memdup2((gconstpointer) &dst_port, sizeof(int)),
				g_memdup2((gconstpointer) &new_count, sizeof(unsigned long)));
			break;
	}
}

/**
 * @brief Initialise packet hash table entry
 * @desc Use data from an existing entry if an entry with the key already exists
 * @param table packet hash table
 * @param key hash table key
 * @param val hash table value
 * @param dst_port destination port
 * @param protocol protocol number (TCP/UDP) of destination port
 */
void init_entry(GHashTable *table, struct key *key, struct value *val,
		int dst_port, int protocol)
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
		val->tcp_ports = current_val->tcp_ports;
		val->udp_ports = current_val->udp_ports;

		/* look up current port's packet count */
		port_count_res = lookup_packet_count(val, dst_port, protocol);

		if (port_count_res) {
			/* increment port count */
			new_port_count = (unsigned long) port_count_res + 1;
		} else {
			/* no packets sent to this port before: set count to 1 and increment
			 * total port count */
			new_port_count = 1;
			val->total_port_count++;
		}

		/* update current port's packet count */
		update_packet_count(val, dst_port, new_port_count, protocol);
	} else {
		/* set up new entry */
		val->first = time(NULL);
		val->latest = val->first;

		/* set up total packet, port, and alert counts */
		val->total_port_count = 1;
		val->total_packet_count = 1;
		val->alert_count = 0;

		/* create new per-port count hash table */
		val->tcp_ports = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, g_free);
		val->udp_ports = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, g_free);
	}
}

/**
 * @brief Update packet hash table entry
 * @param table packet hash table
 * @param key hash table key
 * @param val hash table value
 * @param delete should we delete this entry? (use if IP has been blacklisted)
 */
void update_entry(GHashTable *table, struct key *key, struct value *val,
		  bool delete)
{
	if (delete) {
		/* flagged: destroy IP's port hash tables and remove IP entry from
		 * packet hash table */
		g_hash_table_destroy(val->tcp_ports);
		g_hash_table_destroy(val->udp_ports);
		g_hash_table_remove(table, (gconstpointer)&key->src_ip);
	} else {
		/* insert/update entry */
		g_hash_table_replace(table,
				     g_memdup2((gconstpointer) &key->src_ip, sizeof(in_addr_t)),
				     g_memdup2((gconstpointer) val, sizeof(struct value)));
	}
}

/**
 * @brief Determine whether a description matches the given target
 * @param desc description to check
 * @param target target description
 * @return true if strings match, false otherwise
 */
bool description_match(char *desc, const char *target)
{
	return strncmp(desc, target, strlen(target)) == 0;
}

/**
 * @brief Determine whether all alert types are defined
 * @param types alert_type object to check
 * @return true if all types are defined, false otherwise
 * @details Use to validate objects returned from db_get_alert_types()
 */
bool validate_alert_type(struct alert_type types)
{
	/* check alert types are all defined */
	return (types.XMAS_SCAN != UNDEFINED &&
		types.FIN_SCAN != UNDEFINED &&
		types.NULL_SCAN != UNDEFINED &&
		types.PORT_SCAN != UNDEFINED);
}

/**
 * @brief Read alert type IDs from the database
 * @param conn database connection
 * @param LOG log file to write errors to
 * @return alert_type object
 * @details Read alert types from the `alert_type` table in the existing database connection.
 */
struct alert_type db_get_alert_types(PGconn *conn, FILE *LOG)
{
	PGresult *res = NULL;
	int err = 0;

	struct alert_type types = {
		UNDEFINED,
		UNDEFINED,
		UNDEFINED,
		UNDEFINED
	};

	const struct alert_descriptions DESCS = {
		.XMAS_SCAN = "Xmas scan",
		.FIN_SCAN = "FIN scan",
		.NULL_SCAN = "NULL scan",
		.PORT_SCAN = "Port scan"
	};

	res = PQexec(conn, ALERT_TYPE_QUERY);
	err = (PQresultStatus(res) != PGRES_TUPLES_OK);
	if (err) {
		log_error(LOG, "postgres: %s", PQerrorMessage(conn));
	}

	for (int i = 0; i < PQntuples(res); i++) {
		int id = atoi(PQgetvalue(res, i, 0));  /* ID */
		char *desc = PQgetvalue(res, i, 1);    /* description */

		if (description_match(desc, DESCS.XMAS_SCAN)) {
			types.XMAS_SCAN = id;
		} else if (description_match(desc, DESCS.FIN_SCAN)) {
			types.FIN_SCAN = id;
		} else if (description_match(desc, DESCS.NULL_SCAN)) {
			types.NULL_SCAN = id;
		} else if (description_match(desc, DESCS.PORT_SCAN)) {
			types.PORT_SCAN = id;
		}
	}

	return types;
}

/**
 * @brief Write alert information to database
 * @param conn database connection
 * @param alert_type type of alert (from alert_type enum)
 * @param types alert type object
 * @param key hash table key
 * @param value hash table value
 * @param range destination port range (port-based alerts only)
 * @param dst_port alert destination port (flag-based alerts only)
 * @param LOG log file to write errors to
 * @details Upsert (update/insert) record in `scan_alerts` corresponding to
 * information from the packet hash table
 */
void db_record_scan_alert(PGconn *conn, int alert_type, struct alert_type types,
			struct key *key, struct value *value, struct port_range *range,
			int dst_port, FILE *LOG)
{
	PGresult *db_res;
	int err = 0;
	char query[MAX_QUERY];
	char ip_str[MAX_IP];

	in_addr_t src_ip = key->src_ip;
	inet_ntop(AF_INET, &src_ip, ip_str, MAX_IP);

	if (alert_type == types.PORT_SCAN) {
		/* port-based alert
		 *
		 * destination port is a string colon-delimited range
		 * packet_count = total packet count from src_ip
		 */
		char tcp_port_range[MAX_PORT_RANGE], udp_port_range[MAX_PORT_RANGE];
		int port_count = value->total_port_count;

		format_port_range(tcp_port_range, range->min_tcp, range->max_tcp);
		format_port_range(udp_port_range, range->min_udp, range->max_udp);

		snprintf(query, MAX_QUERY, PORT_ALERT_QUERY, tcp_port_range, udp_port_range, alert_type, ip_str,
			 port_count, value->total_packet_count, value->first, value->latest,
			 /* fields to update */
			 port_count, tcp_port_range, udp_port_range, value->latest,
			 /* only update if packet count and timestamp are newer */
			 value->total_packet_count, value->latest);
	} else {
		/* flag-based alert
		 *
		 * destination is a single port
		 * packet_count = total packet count from src_ip to dst_port
		 */

		snprintf(query, MAX_QUERY, FLAG_ALERT_QUERY, dst_port, alert_type,
			 ip_str, value->total_packet_count, value->first, value->latest,
			 /* fields to update */
			 value->total_packet_count, value->latest,
			 /* only update if packet count and timestamp are newer */
			 value->total_packet_count, value->latest);
	}

	db_res = PQexec(conn, query);

	err = (PQresultStatus(db_res) != PGRES_COMMAND_OK);
	if (err) {
		log_error(LOG, "postgres: %s", PQerrorMessage(conn));
	}

	PQclear(db_res);
}

/**
 * @brief Write blocked IP information to database
 * @param conn database connection
 * @param key hash table key
 * @param value hash table value
 * @param LOG log file to write errors to
 * @details Insert record into `blocked_ips` corresponding to information from
 * the packet hash table
 */
void db_record_blocked_ip(PGconn *conn, struct key *key, struct value *value,
			FILE *LOG)
{
	PGresult *db_res;
	int err = 0;

	char query[MAX_QUERY];
	char ip_str[MAX_IP];

	in_addr_t src_ip = key->src_ip;
	inet_ntop(AF_INET, &src_ip, ip_str, MAX_IP);

	snprintf(query, MAX_QUERY, BLOCKED_IP_QUERY, ip_str, value->latest);

	db_res = PQexec(conn, query);

	err = (PQresultStatus(db_res) != PGRES_COMMAND_OK);
	if (err) {
		log_error(LOG, "postgres: %s", PQerrorMessage(conn));
	}

	PQclear(db_res);
}

/**
 * @brief Connect to PostgreSQL database with *peer authentication*
 * @details Peer authentication: postgres username = system username
 * @param user username
 * @param dbname database name
 * @param LOG log file to write errors to
 * @return the database connection object on success, NULL on error
 */
PGconn *db_connect(char *user, char *dbname, FILE *LOG)
{
	char query[MAX_QUERY];
	PGconn *db;

	snprintf(query, MAX_QUERY, "user=%s dbname=%s", user, dbname);
	db = PQconnectdb(query);

	if (PQstatus(db) != CONNECTION_OK) {
		log_error(LOG, "connection to database failed: %s\n", PQerrorMessage(db));
		/* clean up connection */
		PQfinish(db);
		db = NULL;
	}

	return db;
}

/**
 * @brief Calculate the number of entries in a database task queue (tailq)
 * @param head head of database task queue
 * @return number of entries
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
 * @brief Determine whether a database task queue is full
 * @param head head of database task queue
 * @return 1 if full, 0 otherwise
 */
int queue_full(struct db_task_queue *head)
{
	return queue_size(head) >= MAX_DB_TASKS;
}

/**
 * @brief Queue database work
 * @param task_queue_head head of database work queue
 * @param lock task queue lock
 * @param cond task queue condition
 * @param alert_type type of alert
 * @param types alert type object
 * @param key hash table key
 * @param value hash table value
 * @param dst_port destination port (flag-based alerts only)
 * @param LOG log file to write errors to
 * @return 0 on success, 1 on error (queue full)
 */
int queue_work(struct db_task_queue *task_queue_head, pthread_mutex_t *lock,
	       pthread_cond_t *cond, int alert_type, struct alert_type types,
	       struct key *key, struct value *value, int dst_port, FILE *LOG)
{
	struct db_task *new_task;
	struct port_range *range;

	if (queue_full(task_queue_head)) {
		return 1;
	}

	new_task = malloc(sizeof(struct db_task));
	if (!new_task) {
		/* TODO improve error message */
		p_error("memory allocation failed");
		exit(errno);
	}

	if (alert_type == types.PORT_SCAN) {
		/* port-based alert: min and max ports */
		range = lookup_port_range(value);
		new_task->range = *range;
		free(range);
	} else if (alert_type != UNDEFINED) {
		/* alert type = 0 -> no alert type set
		 * flag-based alert: set destination port */
		new_task->dst_port = dst_port;
	}

	new_task->alert_type = alert_type;
	new_task->types = types;
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
 * @brief Work for database thread
 * @details Wait for work from the task queue and carry it out as it arrives
 * @param args = struct db_thread_args passed to the thread on creation
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

		if (current->alert_type != UNDEFINED) {
			/* write alert to database */
			db_record_scan_alert(db_conn,
					    current->alert_type,
					    current->types,
					    &current->key,
					    &current->value,
					    &current->range,
					    current->dst_port,
					    current->log_file);
		} else {
			/* write flagged IP to database */
			db_record_blocked_ip(db_conn, &current->key, &current->value, current->log_file);
		}

		free(current);
	}
}
