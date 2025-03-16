#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <postgresql/libpq-fe.h>

#define MAX_QUERY 512

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

const struct alert_descriptions DESCS = {
	.XMAS_SCAN = "Xmas scan",
	.FIN_SCAN = "FIN scan",
	.NULL_SCAN = "NULL scan",
	.PORT_SCAN = "Port scan",
};

PGconn *connect_db(char *user, char *dbname)
{
	char query[MAX_QUERY];

	snprintf(query, MAX_QUERY, "user=%s dbname=%s", user, dbname);
	PGconn *db = PQconnectdb(query);
	if (PQstatus(db) != CONNECTION_OK) {
		fprintf(stderr, "connection to database failed: %s\n", PQerrorMessage(db));

		/* clean up connection */
		PQfinish(db);

		return NULL;
	}

	return db;
}

int cmp_description(char *desc, const char *target)
{
	return strncmp(desc, target, strlen(target)) == 0;
}

struct alert_type db_read_alert_type(PGconn *conn)
{
	PGresult *res;
	int err;

	struct alert_type types;
	char *query = "SELECT * FROM alert_type";

	res = PQexec(conn, query);
	err = (PQresultStatus(res) != PGRES_TUPLES_OK);
	if (err) {
		fprintf(stderr, "postgres: %s", PQerrorMessage(conn));
	}

	for (int i = 0; i < PQntuples(res); i++) {
		int id = atoi(PQgetvalue(res, i, 0));  /* ID */
		char *desc = PQgetvalue(res, i, 1);    /* description */

		if (cmp_description(desc, DESCS.XMAS_SCAN)) {
			types.XMAS_SCAN = id;
		} else if (cmp_description(desc, DESCS.FIN_SCAN)) {
			types.FIN_SCAN = id;
		} else if (cmp_description(desc, DESCS.NULL_SCAN)) {
			types.NULL_SCAN = id;
		} else if (cmp_description(desc, DESCS.PORT_SCAN)) {
			types.PORT_SCAN = id;
		}
	}

	PQclear(res);
	return types;
}

int main(int argc, char *argv[])
{
	PGconn *db_conn = connect_db("salma", "sheriff_logbook");
	struct alert_type types;

	types = db_read_alert_type(db_conn);

	printf("xmas = %d, FIN = %d, NULL = %d, port = %d\n",
			types.XMAS_SCAN, types.FIN_SCAN, types.NULL_SCAN, types.PORT_SCAN);
	PQfinish(db_conn);

	return EXIT_SUCCESS;
}
