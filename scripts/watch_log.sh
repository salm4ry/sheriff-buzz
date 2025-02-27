#!/bin/bash

SSH=/usr/bin/ssh
LS=/usr/bin/ls
HEAD=/usr/bin/head

# default username and hostname
host=k0ibian
user=gamek0i

COLOUR="\e[1;34m"  # bold blue
RESET="\e[0m"      # default

print_usage() {
	echo "usage: $0 [-m machine] [-u username]"
}

# helper: run commands on host machine
run_on_host() {
	local SSH_OPTS=-q
	"${SSH}" "${SSH_OPTS}" "${host}" "$@"
}

# latest = log file current sheriff-buzz instance is using
# TODO replace with find(?)
get_log_file () {
	local LS_OPTS='-1t'
	local HEAD_OPTS='-1'
	printf "%s" "$(run_on_host "${LS} ${LS_OPTS} ${log_dir} \
		| ${HEAD} ${HEAD_OPTS}")"
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

# set paths after we get final user argument
root_dir="/home/${user}/sheriff-buzz"
log_dir="${root_dir}"/log

# get log filename
log=$(get_log_file)

printf "${COLOUR}Watching log file %s...${RESET}\n" "${log}"

# follow log file contents
run_on_host "tail -f ${log_dir}/${log}"
