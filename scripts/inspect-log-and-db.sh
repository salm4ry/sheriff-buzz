#!/bin/bash

SSH=/usr/bin/ssh
LS=/usr/bin/ls
HEAD=/usr/bin/head
NMAP=/usr/bin/nmap

DB_NAME="sheriff_logbook"
PORT_SCAN_ALERT=4
# NOTE: have to run sheriff-buzz with -c config.json

# database query: inner join with alert type to get human-readable names
CHECK_QUERY="SELECT COUNT(*) FROM scan_alerts WHERE alert_type = $PORT_SCAN_ALERT;"

LOG_QUERY="SELECT * FROM scan_alerts INNER JOIN alert_type 
	   ON scan_alerts.alert_type = alert_type.id 
	   ORDER BY latest DESC FETCH NEXT 5 ROWS ONLY;"

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

root_dir="/home/$user/sheriff-buzz"
log_dir="$root_dir"/log
config_path="$root_dir"/config

run_on_host() {
	local SSH_OPTS=-q
	"${SSH}" "${SSH_OPTS}" "${host}" "$@"
}

get_log_file () {
	local LS_OPTS='-1t'
	local HEAD_OPTS='-1'
	printf "%s" "$(${LS} ${LS_OPTS} ${log_dir} \
		| ${HEAD} ${HEAD_OPTS})"
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
	current_count=$1
	log=$2
	new_count=$(grep -c 'alert:' "$log_dir/$log")
	return $(( new_count > current_count ))
}

count_alerts() {
	log=$1
	# --csv = CSV format
	# count is on the last output line
	# psql "${DB_NAME}" --csv -c "${CHECK_QUERY}" | tail -1
	grep -c 'alert:' "$log_dir/$log"
}

# set up configuration
#
# testing port-based alert so put a high port threshold and small packet
# threshold
#
# max flag threshold so that we don't block the IP when testing
# initial alert count
#
# get log filename
log=$(get_log_file)

# wait until alert has made it into the log file before continuing
# TODO set timeout

while true
do
	current_count=$(count_alerts "$log")

	printf "current alert count: %d\n" "$current_count"
	printf "waiting for logged alert in %s...\n" "$log"
	while true
	do
		if check_log "$current_count" "$log"
		then
			sleep 1
		else
			# NOTE log file timing measurement ends here
			break
		fi
	done
	# only output alert-related lines
	tac "${log_dir}/${log}" | grep -m5 'alert:'

	PAGER= psql "${DB_NAME}" -c "${LOG_QUERY}"
done


