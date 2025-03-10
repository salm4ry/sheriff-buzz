#ifndef __PACKET_DATA_INTERFACE
#define __PACKET_DATA_INTERFACE

#include <stdbool.h>
#include <arpa/inet.h>
#include <glib-2.0/glib.h>
#include <postgresql/libpq-fe.h>

#include <pthread.h>
#include <sys/queue.h>

#define MAX_QUERY 512
#define MAX_IP 16
#define MAX_IP_HEX 8
#define MAX_PORT_RANGE 12

#define MAX_DB_TASKS 20
#define ALERT_UNDEFINED -1

struct alert_type {
	int XMAS_SCAN;
	int FIN_SCAN;
	int NULL_SCAN;
	int PORT_SCAN;
};

struct alert_descriptions {
	const char *XMAS_SCAN;
	const char *FIN_SCAN;
	const char *NULL_SCAN;
	const char *PORT_SCAN;
};

struct packet_count {
    unsigned int val;
    unsigned int carry; /* carry every 100,000 */
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
	unsigned long total_packet_count;
	int alert_count;
	GHashTable *tcp_ports;
    GHashTable *udp_ports;
};

/* port range for writing port-based alerts to the database */
struct port_range {
	int min;
	int max;
};

struct db_task_queue;

/**
 * Database work queue entry
 *
 * - alert_type: type of alert to be logged
 * - dst_port: alert destination port (flag-based scan)
 * - min_port: min port in port-based scan
 * - max_port: max port in port-based scan
 * - key: hash table key alert is concerned with
 * - value: hash table value alert is concerned with
 * - entries: database workqueue structure
 */
struct db_task {
	int alert_type;
	struct alert_type types;
	int dst_port;
	struct port_range range;
	struct key key;
	struct value value;
	FILE *log_file;
	TAILQ_ENTRY(db_task) entries;
};

TAILQ_HEAD(db_task_queue, db_task);

/**
 * Arguments for database worker thread
 *
 * - head: head of task queue
 * - task_queue_lock: database task queue lock
 * - task_queue_cond: database tack queue condition
 * - db_conn: database connection
 */
struct db_thread_args {
	struct db_task_queue *head;
	pthread_mutex_t *task_queue_lock;
	pthread_cond_t *task_queue_cond;
	PGconn *db_conn;
	FILE *log_file;
};

void min_max_port(gpointer key, gpointer value, gpointer user_data);
struct port_range *lookup_port_range(GHashTable *port_counts);

void destroy_port_tables(gpointer key, gpointer value, gpointer user_data);
void port_table_cleanup(GHashTable *packet_table);

void update_entry_count(gpointer key, gpointer value, gpointer user_data);
int count_entries(GHashTable *table);

void init_entry(GHashTable *table, struct key *key, struct value *val,
		int dst_port);

void update_entry(GHashTable *table, struct key *key, struct value *val,
		bool flagged);

bool description_match(char *desc, const char *target);
struct alert_type db_read_alert_type(PGconn *conn, FILE *LOG);
bool check_alert_type(struct alert_type type);

int db_write_scan_alert(PGconn *conn, int alert_type, struct alert_type types,
		struct key *key, struct value *value, struct port_range *range,
		int dst_port, FILE *LOG);
int db_write_blocked_ip(PGconn *conn, struct key *key, struct value *value,
		FILE *LOG);
PGconn *connect_db(char *user, char *dbname, FILE *LOG);

int queue_size(struct db_task_queue *head);
int queue_full(struct db_task_queue *head);
int queue_work(struct db_task_queue *task_queue_head, pthread_mutex_t *lock,
		pthread_cond_t *cond, int alert_type, struct alert_type types,
		struct key *key, struct value *value, int dst_port, FILE *LOG);

void db_thread_work(void *args);

#endif
