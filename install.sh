#!/bin/bash

# TODO run in/convert to Dockerfile(?)

full_install=${FULL_INSTALL:-false}

sudo apt-get install -y \
	clang \
	make \
	pkg-config \
	libglib2.0-dev \
	libbpf-dev \
	libcjson-dev \
	libpq-dev \
	postgresql

if "$full_install" || [ "$full_install" -eq "1" ]
then
	# install optional dependencies
	sudo apt-get install -y \
		clang-tools \        # for scan-build
		python3-pygments     # for pygmentize
fi

# set up default config file
echo '{
	"packet_threshold": 5,
	"port_threshold": 100,
	"alert_threshold": 3,
	"action": "block",
	"dry_run": false
}' > config/default.json

# create database, granting SELECT access to nonprivileged user
psql postgres -v "username=$USER" -f ./database/create_db.sql
