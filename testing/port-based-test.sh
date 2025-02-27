#!/bin/bash

SSH=/usr/bin/ssh
NMAP=/usr/bin/nmap

# NOTE: have to run sheriff-buzz with -c config.json
# e.g. ./scripts/run-with-config.sh on $host
config_file=config.json

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
config_path="$root_dir"/config

run_on_host() {
	local SSH_OPTS=-q
	"${SSH}" "${SSH_OPTS}" "${host}" "$@"
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

printf "user = %s, hostname = %s, port threshold = %s\n" "$user" "$host" "$num_ports"

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
}' > ${config_path}/${config_file}"

while ! run_on_host "grep -q ${num_ports} ${config_path}/${config_file}"
do
	sleep 1
done

echo "${config_file} updated on disk"

printf "nmap scan on %s\n" "${host}"
nmap_scan "${host}"
