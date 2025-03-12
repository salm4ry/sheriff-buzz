#!/bin/bash

QUERY="SELECT scan_alerts.src_ip, alert_type.description,
           scan_alerts.dst_tcp_port, scan_alerts.dst_udp_port,
	   scan_alerts.port_count, scan_alerts.packet_count,
	   scan_alerts.first, scan_alerts.latest
	   FROM scan_alerts INNER JOIN alert_type
	   ON scan_alerts.alert_type = alert_type.id
	   ORDER BY latest DESC FETCH NEXT 5 ROWS ONLY;"

DB_NAME=sheriff_logbook

# get database alert records (inner join to get human-readable types)
psql "$DB_NAME" -c "$QUERY"
