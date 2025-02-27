#!/bin/bash

QUERY="SELECT * FROM scan_alerts INNER JOIN alert_type 
	   ON scan_alerts.alert_type = alert_type.id;"
DB_NAME=sheriff_logbook

# get database alert records (inner join to get human-readable types)
psql "$DB_NAME" -c "$QUERY"
