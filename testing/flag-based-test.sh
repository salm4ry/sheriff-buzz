#!/bin/bash

SSH=/usr/bin/ssh
SSH_OPTS=-q

LS=/usr/bin/ls
NMAP=/usr/bin/nmap

HEAD=/usr/bin/head
HEAD_OPTS='-1'

CONFIG_FILE=config.json

# used for port number randomisation
NUM_PORTS=65536

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
# min packet threshold
#
# max flag and port threshold so that we don't block the IP when testing!
"${SSH}" "${SSH_OPTS}" "${host}" "echo \
'{
	\"packet_threshold\": 1,
	\"port_threshold\": 65536,
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
