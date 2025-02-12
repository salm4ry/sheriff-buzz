/*
Prerequisites:
- postgres root user with peer authentication exists
- root has the permission CREATEDB (can set using ALERT USER root CREATEDB;)

Run from inside psql using \i alert_database.sql
*/

-- TODO
-- create type alert_type as enum ('Xmas scan', 'FIN scan', 'NULL scan', 'Port scan')

CREATE DATABASE alerts;

-- ensure owner set to root
ALTER DATABASE alerts OWNER TO root;

-- connect to database
\c alerts

/*
tables
NOTE: inet holds IPv4/IPv6 host address (and optionally subnet) in one field
*/

-- alert types
-- TODO replace with enum
CREATE TABLE alert_type(
	id SERIAL PRIMARY KEY,
	description VARCHAR(20)); -- TODO plan scan names: check if max length too short

-- alert log
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

-- flagged IP addresses
create table flagged(
	id SERIAL PRIMARY KEY, -- not strictly required: just for completeness
	src_ip INET,
	time TIMESTAMP  -- time IP was flagged
);

-- alert type foreign key relation
ALTER TABLE IF EXISTS log
	ADD FOREIGN KEY (alert_type)
	REFERENCES alert_type (id) match simple
		ON UPDATE CASCADE
		ON DELETE CASCADE;

-- index for update conflict detection
CREATE UNIQUE INDEX ON log(src_ip, alert_type);

-- set up alert types
-- flag-based scans
INSERT INTO alert_type (description) VALUES('Xmas scan');
INSERT INTO alert_type (description) VALUES('FIN scan');
INSERT INTO alert_type (description) VALUES('NULL scan');
INSERT INTO alert_type (description) VALUES('Port scan');

-- let unprivileged account have permissions
-- before running, set the account to use with:
-- \set username <username>
GRANT SELECT ON log TO :username;
GRANT SELECT ON alert_type TO :username;
GRANT SELECT ON flagged TO :username;
