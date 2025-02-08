#!/bin/bash

HOST=${1:-k0ibian}
NUM_PORTS=${2:-1000}
PORT_SCAN_ALERT=4

ROOT_DIR=/home/gamek0i/port-scan-detector
LOG_DIR="$ROOT_DIR"/log
CONFIG_PATH="$ROOT_DIR"/config
CONFIG_FILE=config.json

SSH=/usr/bin/ssh
LS=/usr/bin/ls
HEAD=/usr/bin/head
NMAP=/usr/bin/nmap

# database query: inner join with alert type to get human-readable names
CHECK_QUERY="SELECT COUNT(*) FROM log WHERE alert_type = $PORT_SCAN_ALERT;"
LOG_QUERY="SELECT log.dst_port, log.src_ip, log.packet_count, log.latest,
	alert_type.description AS alert_type FROM log 
	INNER JOIN alert_type ON log.alert_type = alert_type.id 
	WHERE alert_type = ${PORT_SCAN_ALERT};"


run_on_host() {
	local SSH_OPTS=-q
	"${SSH}" "${SSH_OPTS}" "${HOST}" "$@"
}

get_log_file () {
	local LS_OPTS='-1t'
	local HEAD_OPTS='-1'
	printf "%s" "$(run_on_host "${LS} ${LS_OPTS} ${LOG_DIR} \
		| ${HEAD} ${HEAD_OPTS}")"
}

nmap_scan() {
	local NMAP_OPTS=()

	# nmap with no scan type arguments = top n ports
	NMAP_OPTS+=('-n' '-v0')
	NMAP_OPTS+=('--top-ports' "$NUM_PORTS")
	NMAP_OPTS+=("$1")

	"${NMAP}" "${NMAP_OPTS[@]}"
}

check_log() {
	run_on_host "grep -q alert $LOG_DIR/$log"
}

count_alerts() {
	CHECK_QUERY=$(printf "'%s'" "$CHECK_QUERY")
	# --csv = CSV format
	# count is on the last output line
	run_on_host "psql alerts --csv -c ${CHECK_QUERY}" | tail -1
}

# set up configuration
#
# testing port-based alert so put a high port threshold and small packet
# threshold
#
# max flag threshold so that we don't block the IP when testing
run_on_host "echo \
'{
	\"packet_threshold\": 1,
	\"port_threshold\": ${NUM_PORTS},
	\"flag_threshold\": 10
}' > ${CONFIG_PATH}/${CONFIG_FILE}"

# initial alert count
initial_count=$(count_alerts)

printf "nmap scan on %s\n" "${HOST}"
nmap_scan "${HOST}"
# TODO timing measurement for how long it took the alert to make it to the log
# file + database

# get log filename
log=$(get_log_file)
printf "waiting for logged alert in %s...\n" "$log"

# wait until alert has made it into the log file before continuing
# TODO set timeout
while true
do
	if ! check_log
	then
		sleep 1;
	else
		# NOTE log file timing measurement ends here
		break
	fi
done


# save log to temporary file
tmp_log=$(mktemp -p .)
run_on_host "cat ${LOG_DIR}/$log" > "${tmp_log}"
# only output alert-related lines
grep -m1 'alert: ' "${tmp_log}"
# remove temporary file after use
rm "${tmp_log}"

printf "\nconnecting to %s alert database\n" "${HOST}"

# wait until alert is in database before printing contents
# TODO set timeout
while true
do
	count=$(count_alerts)

	if [[ "$count" > "$initial_count" ]]
	then
		# NOTE database timing measurement ends here
		break
	else
		sleep 1
	fi
done

run_on_host "psql alerts -c '${LOG_QUERY}'"
