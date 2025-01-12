-- flag-based alerts: Xmas, FIN, NULL (packet threshold-based)
INSERT INTO log (fingerprint, dst_port, alert_type, src_ip, packet_count, first, latest)
	VALUES ('%s', '%d', %d, '%s', %d, to_timestamp(%ld), to_timestamp(%ld))
	ON CONFLICT (src_ip, fingerprint, alert_type) WHERE fingerprint IS NOT NULL
		DO UPDATE SET packet_count=%d, latest=to_timestamp(%ld)
		WHERE %d > log.packet_count AND to_timestamp(%ld) > log.latest;


-- port-based alerts (port threshold-based)
INSERT INTO log (dst_port, alert_type, src_ip, port_count, first, latest)
	VALUES ('%s', %d, '%s', %d, to_timestamp(%ld), to_timestamp(%ld))
	ON CONFLICT (src_ip, alert_type) WHERE fingerprint IS NULL
		DO UPDATE SET port_count=%d, dst_port='%s', latest=to_timestamp(%ld)
		WHERE %d > log.port_count AND to_timestamp(%ld) > log.latest
