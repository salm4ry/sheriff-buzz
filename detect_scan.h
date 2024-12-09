#include <linux/stddef.h>
#include <linux/types.h>

#include <postgresql/libpq-fe.h>

#include "pr.h"
#include "packet.h"
#include "parse_headers.h"

#define NUM_PORTS 65536
#define MAX_QUERY 128
#define MAX_PACKETS 1024

/*
 * TCP connection identified by the 4-tuple:
 * (src_ip, src_port, dst_ip, dst_port)
 */
struct connection {
	/* store source IP; destination IP assumed to be localhost */
	long src_ip;
	/* nmap randomises port number by default so don't use to detect scan
	int src_port;
	*/
	/* int dst_port; */
	int packet_count; /* number of packets */
	bool ports_scanned[NUM_PORTS]; /* ports scanned (true/false) */
};

struct packet {
    int dst_port;
    bool flags[NUM_FLAGS];
};

static const char *bool_to_str(bool b)
{
    return b ? "TRUE" : "FALSE";
}

static int count_ports_scanned(struct connection *conn)
{
	int port_count = 0;

	for (int i = 0; i < NUM_PORTS; i++) {
		if (conn->ports_scanned[i]) {
			port_count++;
		}
	}

	return port_count;
}

static bool is_basic_scan(struct connection *conn, int *common_ports, int num_ports)
{
	int common_port_count = 0;
	/* int port_count = count_ports_scanned(conn); */

	for (int i = 0; i < num_ports; i++) {
		if (conn->ports_scanned[common_ports[i]]) {
			common_port_count++;
		}
	}

	return (common_port_count == num_ports);
}

/* detect nmap -sF: FIN only */
static bool is_fin_scan(struct packet *packet)
{
	/* check if FIN enabled */
	if (!packet->flags[FIN]) {
		return false;
	}

	/* iterate through flag enum */
	for (int i = SYN; i <= CWR; i++) {
		if (packet->flags[i]) {
			return false;
		}
	}
	return true;
}

/* detect nmap -sX: FIN + PSH + URG */
static int is_xmas_scan(struct packet *packet) {
	return (packet->flags[FIN] && packet->flags[PSH] && packet->flags[URG]);
}

/* no flags set */
static int is_null_scan(struct connection *conn, struct packet *packet) {
	/* check we actually have received packets
	 * TODO change the 1 to list of legitimate ports to receive traffic from */
	if (conn->packet_count == 0 || count_ports_scanned(conn) == 1) {
		return false;
	}

	for (int i = FIN; i <= CWR; i++) {
		if (packet->flags[i]) {
			return false;
		}
	}
	return true;
}

static int db_cleanup(PGconn *db_conn, PGresult *res)
{
	pr_err("postgres: %s\n", PQerrorMessage(db_conn));
    PQclear(res);
    PQfinish(db_conn);
    return 1;
}

/* connect to postgres database with peer authentication 
 * (postgres username = system username) */
static PGconn *connect_db(char *user, char *dbname)
{
	char query[1024];

	sprintf(query, "user=%s dbname=%s", user, dbname);
	PGconn *conn = PQconnectdb(query);
	if (PQstatus(conn) == CONNECTION_BAD) {
		pr_err("connection to database failed: %s\n",
				PQerrorMessage(conn));
		PQfinish(conn);
		/* return NULL on error */
		return NULL;
	}

	return conn;
}

/* create packet and connection tables */
static int create_tables(PGconn *db_conn)
{
    /* TODO replace with prepared statements */

	/* drop old connection table (if there is one)
	 * cascade in order to remove dependent objects (records in packet table)
	 */
	PGresult *res = PQexec(db_conn, "DROP TABLE IF EXISTS connection CASCADE");
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		return db_cleanup(db_conn, res);
	}
	PQclear(res);

	/* connection table fields:
	 * id: primary key
	 * src_ip: source IP address
	 * packet_count: number of packets from connection
	 */
	res = PQexec(db_conn, "CREATE TABLE connection(src_ip BIGINT PRIMARY KEY, "\
                          "packet_count INTEGER)"
	);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		return db_cleanup(db_conn, res);
	}
	PQclear(res);

	/* drop old packet table (if there is one) */
	res = PQexec(db_conn, "DROP TABLE IF EXISTS packet");
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		return db_cleanup(db_conn, res);
	}
	PQclear(res);

	/* packet table fields:
	 * id: primary key
	 * dst_port: destination port
	 * conn_id: foreign key for connection
	 * boolean fields for each flag
	 */
	res = PQexec(db_conn, "CREATE TABLE packet(id SERIAL PRIMARY KEY," \
			   "dst_port INTEGER, conn_id BIGINT,"\
	      		   "fin BOOL, syn BOOL, rst BOOL, psh BOOL,"\
		           "ack BOOL, urg BOOL, ece BOOL, cwr BOOL)"
	);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		return db_cleanup(db_conn, res);
	}
	PQclear(res);

	/* add packet table foreign key -> conn_id 
	 *
	 * cascade = any changes made in foreign table apply to primary table
	 * e.g. deleting a connection would delete its associated packets
	 */
	res = PQexec(db_conn, "ALTER TABLE IF EXISTS packet " \
			   "ADD FOREIGN KEY (conn_id) REFERENCES connection (src_ip) MATCH SIMPLE " \
			   "ON UPDATE CASCADE " \
			   "ON DELETE CASCADE"
	);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		return db_cleanup(db_conn, res);
	}
	PQclear(res);

	return 0;
}

static int edit_connection(PGconn *db_conn, struct connection *new_connection)
{
    char query[MAX_QUERY];
    PGresult *res;
    int rows;

    /* TODO replace with prepared statements */

    /* check if connection record for provided IP already exists */
    sprintf(query, "SELECT src_ip FROM connection WHERE src_ip = %ld",
            new_connection->src_ip);
    res = PQexec(db_conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        return db_cleanup(db_conn, res);
    }
    /* number of rows in query (non-zero means record already exists) */
    rows = PQntuples(res);
    PQclear(res);
    if (rows != 0) {
        /* connection record already exists; simply update packet count */
        if (new_connection->packet_count >= MAX_PACKETS) {
            /* don't update if exceeded max number of packets */
            return 0;
        }

        sprintf(query, "UPDATE connection SET packet_count = %d WHERE src_ip = %ld",
                new_connection->packet_count, new_connection->src_ip);
        res = PQexec(db_conn, query);
        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            return db_cleanup(db_conn, res);
        }
        return 0;
    }

    /* add new connection record */
    sprintf(query, "INSERT INTO connection VALUES(%ld, %d)",
            new_connection->src_ip, new_connection->packet_count);

    res = PQexec(db_conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        return db_cleanup(db_conn, res);
    }
    PQclear(res);

    return 0;
}

static int add_packet(PGconn *db_conn, struct connection *current_conn, struct packet *new_packet)
{
    char query[MAX_QUERY];
    PGresult *res;
    const char *flags[NUM_FLAGS];

    /* TODO potentially only add if new port scanned from a given IP? can do a
     * SELECT */

    if (current_conn->packet_count >= MAX_PACKETS) {
        /* we're over the limit -> do nothing */
        return 0;
    }

    for (int i = 0; i < NUM_FLAGS; i++) {
        flags[i] = bool_to_str(new_packet->flags[i]);
    }

    sprintf(query, "INSERT INTO packet (dst_port, conn_id, "\
                   "fin, syn, rst, psh, ack, urg, ece, cwr) " \
                   "VALUES(%d, %ld, "\
                   "%s, %s, %s, %s, %s, %s, %s, %s)",
                   new_packet->dst_port, current_conn->src_ip,
                   flags[FIN], flags[SYN], flags[RST], flags[PSH],
                   flags[ACK], flags[URG], flags[ECE], flags[CWR]);

    res = PQexec(db_conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        return db_cleanup(db_conn, res);
    }
    PQclear(res);
    return 0;
}
