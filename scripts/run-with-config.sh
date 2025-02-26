#!/bin/bash

user=gamek0i

print_usage() {
	echo "usage: $0 [-u username]"
}

while getopts 'u:h' OPTION
do
	case "${OPTION}" in
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

dir="/home/${user}/sheriff-buzz"
prog=sheriff-buzz

# default interface
interface=$(ip route show default | awk '{ print $5 }')

# config file at config/config.json
config_file=config.json

# run with user-supplied config file
sudo "${dir}"/"${prog}" -i "${interface}" -c "${config_file}"
