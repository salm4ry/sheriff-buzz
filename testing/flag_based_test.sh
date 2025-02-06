#!/bin/bash

NUM_PORTS=65536

HOST=${1:-k0ibian}
ROOT_DIR=/home/gamek0i/port-scan-detector
LOG_DIR="$ROOT_DIR"/log
CONFIG_PATH="$ROOT_DIR"/config
CONFIG_FILE=config.json

SSH=/usr/bin/ssh
SSH_OPTS=-q

LS=/usr/bin/ls

HEAD=/usr/bin/head
HEAD_OPTS='-1'

NMAP=/usr/bin/nmap

# database query: inner join with alert type to get human-readable names
LOG_QUERY='SELECT log.dst_port, log.src_ip, log.packet_count, log.latest,
	alert_type.description AS alert_type FROM log 
	INNER JOIN alert_type ON log.alert_type = alert_type.id;'

# TODO document test script e.g. in README

# generate pseudorandom port numbers for testing
rand_port () {
	printf "%d" $(( RANDOM % NUM_PORTS ))
}

# get name of latest log file (assumption that the program is already running so
# has already created a log file)
get_log_file () {
	local LS_OPTS='-1t'
	printf "%s" "$("${SSH}" "${SSH_OPTS}" "${HOST}" \
		"${LS} ${LS_OPTS} ${LOG_DIR} \
		| ${HEAD} ${HEAD_OPTS}")"
}

nmap_scan() {
	local scan_type=$1
	local NMAP_OPTS=()

	# -n = never use DNS
	# -v0 = remove stdout output
	NMAP_OPTS+=('-n' '-v0')

	case $scan_type in
		xmas)
			NMAP_OPTS+=('-sX')
			;;
		fin)
			NMAP_OPTS+=('-sF')
			;;
		null)
			NMAP_OPTS+=('-sN')
			;;
		default)
			NMAP_OPTS+=('')
			;;
	esac

	NMAP_OPTS+=('-p' "$2" "$3")
	sudo "${NMAP}" "${NMAP_OPTS[@]}"
}

# set up configuration
#
# only testing that the different scan types are recorded correctly so we use
# small packet and port thresholds
#
# max flag threshold so that we don't block the IP when testing!
"${SSH}" "${SSH_OPTS}" "${HOST}" "echo \
'{
	\"packet_threshold\": 1,
	\"port_threshold\": 10,
	\"flag_threshold\": 10
}' > ${CONFIG_PATH}/${CONFIG_FILE}"

# Xmas scan
port=$(rand_port)
printf "Xmas scan on port %d\n" "$port"
nmap_scan xmas "$port" "${HOST}"

# FIN scan
port=$(rand_port)
printf "FIN scan on port %d\n" "$port"
nmap_scan fin "$port" "${HOST}"

# NULL scan
port=$(rand_port)
printf "NULL scan on port %d\n" "$port"
nmap_scan null "$port" "${HOST}"

# get log file contents
log=$(get_log_file)
printf "\nusing log file: %s\n" "$log"

# save log to temporary file
tmp_log=$(mktemp -p .)
"${SSH}" "${SSH_OPTS}" "${HOST}" "cat ${LOG_DIR}/$log" > "${tmp_log}"
# only output alert-related lines
grep 'alert: ' "${tmp_log}"
# remove temporary file after use
rm "${tmp_log}"

# check alerts were added to the database correctly
printf "\nconnecting to %s alert database\n" "${HOST}"
"${SSH}" "${SSH_OPTS}" "${HOST}" "psql alerts -c '${LOG_QUERY}'"
