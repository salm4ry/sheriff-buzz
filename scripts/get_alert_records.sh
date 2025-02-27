#!/bin/bash

QUERY="SELECT * FROM scan_alerts INNER JOIN alert_type 
	   ON scan_alerts.alert_type = alert_type.id;"
DB_NAME=sheriff_logbook

psql "$DB_NAME" -c "$QUERY"
