/// @file

#ifndef __PACKET_DATA_INTERFACE
#define __PACKET_DATA_INTERFACE

#include <stdbool.h>
#include <arpa/inet.h>
#include <glib-2.0/glib.h>
#include <postgresql/libpq-fe.h>

#include <pthread.h>
#include <sys/queue.h>

#define MAX_QUERY 512  ///< maximum database query length
#define MAX_IP 16  ///< maximum IPv4 presentation format length
#define MAX_IP_HEX 8  ///< maximum IP string length (hexadecimal)
#define MAX_PORT_RANGE 12  ///< maximum port range string length

#define MAX_DB_TASKS 20  ///< maximum work queue size
#define UNDEFINED -1  ///< undefined alert type

#define INIT_MAX_PORT -1  ///< starting maximum port in lookup_port_range()
#define INIT_MIN_PORT 65536  ///< starting minimum port in lookup_port_range()

/**
 * @brief SELECT query to get available alert types
 */
static const char *ALERT_TYPE_QUERY = "SELECT * from alert_type";

/**
 * @brief INSERT query to record a port-based alert
 */
static const char *PORT_ALERT_QUERY = "INSERT INTO scan_alerts (dst_tcp_port, dst_udp_port, alert_type, src_ip, port_count, packet_count, first, latest) "
				      "VALUES ('%s', '%s', %d, '%s', %d, %d, to_timestamp(%ld), to_timestamp(%ld)) "
				      "ON CONFLICT (src_ip, dst_tcp_port, dst_udp_port, alert_type) "
				      "DO UPDATE SET port_count=%d, dst_tcp_port='%s', dst_udp_port='%s', latest=to_timestamp(%ld) "
				      "WHERE %d > scan_alerts.packet_count AND to_timestamp(%ld) > scan_alerts.latest";

/**
 * @brief INSERT query to record a flag-based alert
 */
static const char *FLAG_ALERT_QUERY = "INSERT INTO scan_alerts (dst_tcp_port, dst_udp_port, alert_type, src_ip, packet_count, first, latest) "
				      "VALUES ('%d', '', %d, '%s', %d, to_timestamp(%ld), to_timestamp(%ld)) "
				      "ON CONFLICT (src_ip, dst_tcp_port, dst_udp_port, alert_type) "
				      "DO UPDATE SET packet_count=%d, latest=to_timestamp(%ld) "
				      "WHERE %d > scan_alerts.packet_count AND to_timestamp(%ld) > scan_alerts.latest";

/**
 * @brief INSERT query to record a blocked IP
 */
static const char *BLOCKED_IP_QUERY = "INSERT INTO blocked_ips (src_ip, time) VALUES ('%s', to_timestamp(%ld))";

/**
 * @brief Alert type IDs from database
 */
struct alert_type {
	int XMAS_SCAN;
	int FIN_SCAN;
	int NULL_SCAN;
	int PORT_SCAN;
};

/**
 * @brief Alert descriptions
 * @details Used to look up alert_type IDs in database
 */
struct alert_descriptions {
	const char *XMAS_SCAN;
	const char *FIN_SCAN;
	const char *NULL_SCAN;
	const char *PORT_SCAN;
};

/**
 * @brief Hash table key
 */
struct key {
	in_addr_t src_ip;  ///< source IP
};

/**
 * @brief Hash table value
 */
struct value {
	time_t first;  ///< timestamp of first packet received
	time_t latest; ///< timestamp of latest packet received
	int total_port_count;  ///< total number of ports IP has sent packets to
	unsigned long total_packet_count;  ///< total number packets IP has sent
	int alert_count;  ///< number of alerts triggered by IP
	GHashTable *tcp_ports;  ///< packet counts per TCP port
	GHashTable *udp_ports;  ///< packet counts per UDP port
};

/**
 * @brief Port range
 * @details Used to record port-based alerts in the database
 */
struct port_range {
	int min_tcp;  ///< minimum TCP port
	int max_tcp;  ///< maximum TCP port
	int min_udp;  ///< minimum UDP port
	int max_udp;  ///< maximum UDP port
};

/**
 * @brief lookup_port_range() context
 */
struct port_lookup_ctx {
	struct port_range *range;  ///< current port range
	int protocol;  ///< protocol to update port values of
};

/**
 * @brief Database work queue entry
 */
struct db_task {
	int alert_type;  ///< type of alert to be recorded
	struct alert_type types;  ///< alert destination port (flag-based scan)
	int dst_port;  ///< minimum port (port-based scan)
	struct port_range range;  ///< maximum port (port-based scan)
	struct key key;  ///<  packet hash table key
	struct value value;  ///< packet hash table value
	FILE *log_file;  ///< log file
	TAILQ_ENTRY(db_task) entries;  ///< database workqueue
};

/**
 * @struct db_task_queue
 * @brief Database workqueue structure
 */
struct db_task_queue;
/**
 * @brief Create database workqueue structure
 */
TAILQ_HEAD(db_task_queue, db_task);

/**
 * @brief Database worker thread arguments
 */
struct db_thread_args {
	struct db_task_queue *head;  ///< head of database workqueue
	pthread_mutex_t *task_queue_lock;  ///< database task queue lock
	pthread_cond_t *task_queue_cond;  ///< database task queue condition
	PGconn *db_conn;  ///< database connection
	FILE *log_file;  ///< log file
};

void min_max_port(gpointer key, gpointer value, gpointer user_data);
struct port_range *lookup_port_range(struct value *val);
void format_port_range(char *buf, int min, int max);

void destroy_port_tables(gpointer key, gpointer value, gpointer user_data);
void port_table_cleanup(GHashTable *packet_table);

gpointer lookup_packet_count(struct value *val, int dst_port, int protocol);
void update_packet_count(struct value *val, int dst_port, int new_count,
		int protocol);

void update_entry_count(gpointer key, gpointer value, gpointer user_data);
int count_entries(GHashTable *table);

void init_entry(GHashTable *table, struct key *key, struct value *val,
		int dst_port, int protocol);

void update_entry(GHashTable *table, struct key *key, struct value *val,
		bool delete);

bool description_match(char *desc, const char *target);
struct alert_type db_get_alert_types(PGconn *conn, FILE *LOG);
bool validate_alert_type(struct alert_type type);

void db_record_scan_alert(PGconn *conn, int alert_type, struct alert_type types,
		struct key *key, struct value *value, struct port_range *range,
		int dst_port, FILE *LOG);
void db_record_blocked_ip(PGconn *conn, struct key *key, struct value *value,
		FILE *LOG);
PGconn *db_connect(char *user, char *dbname, FILE *LOG);

int queue_size(struct db_task_queue *head);
int queue_full(struct db_task_queue *head);
int queue_work(struct db_task_queue *task_queue_head, pthread_mutex_t *lock,
		pthread_cond_t *cond, int alert_type, struct alert_type types,
		struct key *key, struct value *value, int dst_port, FILE *LOG);

void db_thread_work(void *args);

#endif
