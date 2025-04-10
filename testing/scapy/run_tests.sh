#!/bin/bash

venv_dir='.venv'
venv_python='.venv/bin/python3'

# set test script capabilities
# CAP_NET_RAW: use raw sockets (for sending test packets)
#
# CAP_DAC_OVERRIDE: bypass file read, write, and execute permission checks (to
# read the BPF map)
#
# e = effective, p = permitted
unit_test_caps='CAP_NET_RAW,CAP_DAC_OVERRIDE=+ep'
integration_test_caps='CAP_NET_RAW=+ep'

LOCALHOST=127.0.0.1

usage="-u: run unit tests
-i: run integration tests,
-n: number of packets to send (default 100)"

run_unit=false
run_integration=false
num_packets=100

clear_cap() {
	# remove capabilities on .venv Python interpreter
	sudo setcap -r "${venv_python}"
}

activate() {
	source "${venv_dir}/bin/activate"
}

unit_tests() {
	# set unit testing capabilities
	sudo setcap "${unit_test_caps}" "${venv_python}"
	# run unit tests
	"${venv_python}" unit_tests.py -t "${LOCALHOST}"
	clear_cap
	echo '-----'
}

integration_tests() {
	# set new capabilities for integration testing
	sudo setcap "${integration_test_caps}" "${venv_python}"
	# run integration tests
	"${venv_python}" integration_tests.py -t "${LOCALHOST}" -n "${1}"
	clear_cap
	echo '-----'
}

print_usage() {
	echo "usage: $0 [-u] [-i] [-n num_packets]"
	echo "${usage}"
}

# parse command-line arguments
while getopts 'huin:' OPTION
do
	case "${OPTION}" in
		u)
			run_unit=true
			;;
		i)
			run_integration=true
			;;
		n)
			num_packets=$OPTARG
			;;
		h)
			print_usage
			exit 0
			;;
		?)
			print_usage
			exit 1
	esac
done

# activate virtual environment
# (follow instructions in README.md to create the .venv directory)
activate

if $run_unit
then
	unit_tests
fi

if $run_integration
then
	integration_tests "${num_packets}"
fi

# deactivate virtual environment
deactivate
