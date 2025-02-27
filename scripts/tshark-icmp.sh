#!/bin/bash

interface=$(ip route show default | awk '{ print $5 }')
host=k0ibian

print_usage() {
	echo "usage: $0 [-m machine] [-i interface]"
}

while getopts 'i:m:h' OPTION
do
	case "${OPTION}" in
		m)
			host=$OPTARG
			;;
		i)
			interface=$OPTARG
			;;
		h)
			print_usage
			exit 0
			;;
		?)
			print_usage
			exit 0
			;;
	esac
done

echo "display filter: host ${host} and icmp"
tshark --color -i "${interface}" -f "host ${host} and icmp"
