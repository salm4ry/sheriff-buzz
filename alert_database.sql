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
	dst_port INTEGER,
	alert_type INTEGER,
	src_ip INET,
	packet_count INTEGER,
	first TIMESTAMP,
	latest TIMESTAMP);

-- foreign key relation
ALTER TABLE IF EXISTS log
	ADD FOREIGN KEY (alert_type)
	REFERENCES alert_type (id) match simple
		ON UPDATE CASCADE
		ON DELETE CASCADE;

-- index for update conflict detection
CREATE UNIQUE INDEX log_index ON log(fingerprint, alert_type);

-- set up alert types
-- flag-based scans
INSERT INTO alert_type (description) VALUES('Xmas scan');
INSERT INTO alert_type (description) VALUES('FIN scan');
INSERT INTO alert_type (description) VALUES('NULL scan');

-- TODO more scan types
