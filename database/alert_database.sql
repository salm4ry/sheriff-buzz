-- DROP DATABASE if exists alerts;
CREATE DATABASE alerts;

-- ensure owner set to root
ALTER DATABASE alerts OWNER TO root;

-- connect to database
\c alerts

/*
tables
NOTE: inet holds IPv4/IPv6 host address (and optionally subnet) in one field
*/
CREATE TABLE alert_type(
	id SERIAL PRIMARY KEY,
	description VARCHAR(20)); -- TODO plan scan names: check if max length too short

CREATE TABLE log(
	id SERIAL PRIMARY KEY,
	fingerprint CHAR(12),
	dst_port VARCHAR(11), -- either single port or lowest:highest depending on scan type
	alert_type INTEGER,
	src_ip INET,
	packet_count INTEGER,
	port_count INTEGER,   -- number of ports scanned- used for port-based alert
	first TIMESTAMP,
	latest TIMESTAMP);

-- foreign key relation
ALTER TABLE IF EXISTS log
	ADD FOREIGN KEY (alert_type)
	REFERENCES alert_type (id) match simple
		ON UPDATE CASCADE
		ON DELETE CASCADE;

-- index for update conflict detection
CREATE UNIQUE INDEX ON log(fingerprint, src_ip, alert_type)
	WHERE fingerprint IS NOT NULL;

CREATE UNIQUE INDEX ON log(src_ip, alert_type)
	WHERE fingerprint IS NULL;

-- set up alert types
-- flag-based scans
INSERT INTO alert_type (description) VALUES('Xmas scan');
INSERT INTO alert_type (description) VALUES('FIN scan');
INSERT INTO alert_type (description) VALUES('NULL scan');
INSERT INTO alert_type (description) VALUES('Basic port scan');
