#!/bin/bash

SSH=/usr/bin/ssh
SSH_OPTS=-q

LS=/usr/bin/ls
NMAP=/usr/bin/nmap

HEAD=/usr/bin/head
HEAD_OPTS='-1'

DB_NAME="sheriff_logbook"
# NOTE: have to run sheriff-buzz with -c config.json
CONFIG_FILE=config.json

# used for port number randomisation
NUM_PORTS=65536

# database query: inner join with alert type to get human-readable names
LOG_QUERY='SELECT scan_alerts.dst_port, scan_alerts.src_ip,
	scan_alerts.packet_count, scan_alerts.latest,
	alert_type.description AS alert_type FROM scan_alerts
	INNER JOIN alert_type ON scan_alerts.alert_type = alert_type.id;'

# default arguments
host=k0ibian
user=gamek0i


print_usage() {
	echo "usage: $0 [-m machine] [-u username]"
}

while getopts 'hu:m:' OPTION
do
	case "${OPTION}" in
		m)
			host=$OPTARG
			;;
		u)
			user=$OPTARG
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

# TODO document test script e.g. in README

# generate pseudorandom port numbers for testing
rand_port () {
	printf "%d" $(( RANDOM % NUM_PORTS ))
}

# get name of latest log file (assumption that the program is already running so
# has already created a log file)
get_log_file () {
	local LS_OPTS='-1t'
	printf "%s" "$("${SSH}" "${SSH_OPTS}" "${host}" \
		"${LS} ${LS_OPTS} ${log_dir} \
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
"${SSH}" "${SSH_OPTS}" "${host}" "echo \
'{
	\"packet_threshold\": 1,
	\"port_threshold\": 10,
	\"alert_threshold\": 10
}' > ${config_path}/${CONFIG_FILE}"

printf "%s@%s\n" "${user}" "${host}"

# Xmas scan
port=$(rand_port)
printf "Xmas scan on port %d\n" "$port"
nmap_scan xmas "$port" "${host}"

# FIN scan
port=$(rand_port)
printf "FIN scan on port %d\n" "$port"
nmap_scan fin "$port" "${host}"

# NULL scan
port=$(rand_port)
printf "NULL scan on port %d\n" "$port"
nmap_scan null "$port" "${host}"

# get log file contents
log=$(get_log_file)
printf "\nusing log file: %s\n" "$log"

# save log to temporary file
tmp_log=$(mktemp -p .)
"${SSH}" "${SSH_OPTS}" "${host}" "cat ${log_dir}/$log" > "${tmp_log}"
# only output alert-related lines
grep 'alert: ' "${tmp_log}"
# remove temporary file after use
rm "${tmp_log}"

# check alerts were added to the database correctly
printf "\nconnecting to %s alert database\n" "${host}"
"${SSH}" "${SSH_OPTS}" "${host}" "psql ${DB_NAME} -c '${LOG_QUERY}'"
