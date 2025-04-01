#!/bin/bash

HPING3=/sbin/hping3

config=  # config file path
flags=   # TCP flags
ports=   # ports to send packets to
src_ip=  # source IP address (spoof)
target=  # target IP address

print_usage() {
	echo "usage: $0 -c <config> [-t <target> -p <ports> -s <src_ip> -f <flags>]"
}

# run hping silently
gen_traffic() {
	sudo "${HPING3}" -q -a "${src_ip}" \
		--scan "${ports}" "${flags[@]}" "${target}"
}

print_cmd() {
	echo sudo "${HPING3}" -q -a "${src_ip}" \
		--scan "${ports}" "${flags[@]}" "${target}"
}


run_test() {
	echo 'Running test'
	gen_traffic > /dev/null 2>&1
	err=$?

	# check return code
	if [ $err -ne 0 ]
	then
		print_cmd
		gen_traffic
		exit "$err"
	else
		echo 'Test complete!'
	fi
}

while getopts 'hc:f:p:s:t:' OPTION
do
	case "${OPTION}" in
		c)
			config=$OPTARG

			# NOTE sourcing here allows us to overwrite parts of the
			# config with command-line arguments
			source "$config"
			;;
		f)
			readarray -d ' ' -t flags <<< "$OPTARG"
			flags=(${flags[*]})  # split words (remove whitespace)
			declare -p flags
			;;
		p)
			ports=$OPTARG
			;;
		s)
			src_ip=$OPTARG
			;;
		t)
			target=$OPTARG
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

if [ $OPTIND -eq 1 ]
then
	echo 'error: no arguments supplied'
	print_usage
	exit 1
fi

run_test
