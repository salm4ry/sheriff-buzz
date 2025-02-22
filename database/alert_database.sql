/*
Prerequisites:
- postgres root user with peer authentication exists
- root has the permission CREATEDB (can set using ALERT USER root CREATEDB;)

Run from inside psql using \i alert_database.sql
*/

-- TODO rename to program name
CREATE DATABASE packet;

-- ensure owner set to root
ALTER DATABASE packet OWNER TO root;

-- connect to database
\c packet

/*
tables
NOTE: inet holds IPv4/IPv6 host address (and optionally subnet) in one field
*/

-- alert types
CREATE TABLE alert_type(
	id SERIAL PRIMARY KEY,
	description VARCHAR(20)); -- max length 20 characters

-- alert log
CREATE TABLE scan_alerts(
	id SERIAL PRIMARY KEY,
	dst_port VARCHAR(11), -- either single port or lowest:highest (max length 11) depending on scan type
	alert_type INTEGER,
	src_ip INET,
	packet_count INTEGER,
	port_count INTEGER,   -- number of ports scanned (port-based alert)
	first TIMESTAMP,      -- time of first packet
	latest TIMESTAMP);    -- time of latest packet

-- IP addresses blocked by the program (as opposed to config blacklist)
create table blocked_ips(
	id SERIAL PRIMARY KEY, -- not strictly required: just for completeness
	src_ip INET,
	time TIMESTAMP  -- time of block
);

-- alert type foreign key relation
ALTER TABLE IF EXISTS scan_alerts
	ADD FOREIGN KEY (alert_type)
	REFERENCES alert_type (id) match simple
		ON UPDATE CASCADE
		ON DELETE CASCADE;

-- index for update conflict detection
CREATE UNIQUE INDEX ON scan_alerts(src_ip, dst_port, alert_type);

-- set up alert types
-- flag-based scans
INSERT INTO alert_type (description) VALUES('Xmas scan');
INSERT INTO alert_type (description) VALUES('FIN scan');
INSERT INTO alert_type (description) VALUES('NULL scan');
INSERT INTO alert_type (description) VALUES('Port scan');

-- let unprivileged account have permissions
-- before running, set the account to use with:
-- \set username <username>
GRANT SELECT ON scan_alerts TO :username;
GRANT SELECT ON alert_type TO :username;
GRANT SELECT ON blocked_ips TO :username;
