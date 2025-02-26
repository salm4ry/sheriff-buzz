#!/bin/bash

SSH=/usr/bin/ssh
LS=/usr/bin/ls
HEAD=/usr/bin/head
NMAP=/usr/bin/nmap

# database query: inner join with alert type to get human-readable names
CHECK_QUERY="SELECT COUNT(*) FROM scan_alerts WHERE alert_type = $PORT_SCAN_ALERT;"
LOG_QUERY="SELECT scan_alerts.dst_port, scan_alerts.src_ip,
	scan_alerts.packet_count, scan_alerts.latest,
	alert_type.description AS alert_type FROM scan_alerts
	INNER JOIN alert_type ON scan_alerts.alert_type = alert_type.id
	WHERE alert_type = ${PORT_SCAN_ALERT};"

DB_NAME="sheriff_logbook"
PORT_SCAN_ALERT=4
# NOTE: have to run sheriff-buzz with -c config.json
CONFIG_FILE=config.json

# default arguments
host=k0ibian
user=gamek0i
num_ports=1000

print_usage() {
	echo "usage: $0 [-m machine] [-u username] [-n number of ports]"
}

while getopts 'hu:m:n:' OPTION
do
	case "${OPTION}" in
		m)
			host=$OPTARG
			;;
		u)
			user=$OPTARG
			;;
		n)
			num_ports=$OPTARG
			;;
		h)
			print_usage
			exit 0
			;;
		?)
			print_usage
			exit 1
			;;
	esac
done

root_dir="/home/$USER/sheriff-buzz"
log_dir="$root_dir"/log
config_path="$root_dir"/config

run_on_host() {
	local SSH_OPTS=-q
	"${SSH}" "${SSH_OPTS}" "${host}" "$@"
}

get_log_file () {
	local LS_OPTS='-1t'
	local HEAD_OPTS='-1'
	printf "%s" "$(run_on_host "${LS} ${LS_OPTS} ${log_dir} \
		| ${HEAD} ${HEAD_OPTS}")"
}

nmap_scan() {
	local NMAP_OPTS=()

	# nmap with no scan type arguments = top n ports
	# NMAP_OPTS+=('-n' '-v0')
	NMAP_OPTS+=('-n')

	if [[ $num_ports -le 1000 ]]; then
		NMAP_OPTS+=('--top-ports' "$num_ports")
	else
		NMAP_OPTS+=('-p' "1-$num_ports")
	fi

	NMAP_OPTS+=("$1")

	echo "${NMAP}" "${NMAP_OPTS[@]}"
	"${NMAP}" "${NMAP_OPTS[@]}"
}

check_log() {
	run_on_host "grep -q alert $log_dir/$log"
}

count_alerts() {
	CHECK_QUERY=$(printf "'%s'" "$CHECK_QUERY")
	# --csv = CSV format
	# count is on the last output line
	run_on_host "psql ${DB_NAME} --csv -c ${CHECK_QUERY}" | tail -1
}

printf "%s@%s, port threshold = %s\n" "$user" "$host" "$num_ports"

# set up configuration
#
# testing port-based alert so put a high port threshold and small packet
# threshold
#
# max flag threshold so that we don't block the IP when testing
run_on_host "echo \
'{
	\"packet_threshold\": 1,
	\"port_threshold\": ${num_ports},
	\"alert_threshold\": 10
}' > ${config_path}/${CONFIG_FILE}"

# initial alert count
initial_count=$(count_alerts)
printf "initial alert count: %d\n" "$initial_count"

printf "nmap scan on %s\n" "${host}"
nmap_scan "${host}"
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
		run_on_host "tail -1 $log_dir/$log"
		sleep 1;
	else
		# NOTE log file timing measurement ends here
		break
	fi
done


# save log to temporary file
tmp_log=$(mktemp -p .)
run_on_host "cat ${log_dir}/$log" > "${tmp_log}"
# only output alert-related lines
grep -m1 'alert: ' "${tmp_log}"
# remove temporary file after use
rm "${tmp_log}"

printf "\nconnecting to %s alert database\n" "${host}"

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
		printf "number of alerts: %d\n" "$count"
		sleep 1
	fi
done

run_on_host "psql ${DB_NAME} -c '${LOG_QUERY}'"
