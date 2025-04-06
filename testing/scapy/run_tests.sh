#!/bin/bash

dir="${HOME}/sheriff-buzz"
prog=sheriff-buzz
interface=lo
config_file="${dir}/config.json"
venv_dir='.venv'
bpf_obj="${dir}/src/sheriff-buzz.bpf.o"
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

start_buzz() {
	# run sheriff-buzz on loopback interface, setting config file location
	# and enabling testing mode
	sudo -b "${dir}/${prog}" -i "${interface}" -c "${config_file}" -b "${bpf_obj}" -t
}

stop_buzz() {
	sudo killall "${prog}"
}

clear_cap() {
	# remove capabilities on .venv Python interpreter
	sudo setcap -r "${venv_python}"
}


# activate virtual environment
# (follow instructions in README.md to create the .venv directory)
source "${venv_dir}"/bin/activate

# set unit testing capabilities
sudo setcap "${unit_test_caps}" "${venv_python}"
start_buzz
# run unit tests
"${venv_python}" unit_tests.py -u "${USER}" -t "${LOCALHOST}"
stop_buzz  # required to clear blacklists and whitelists
clear_cap

start_buzz
# set new capabilities for integration testing
sudo setcap "${integration_test_caps}" "${venv_python}"
# run integration tests
echo '-----'
"${venv_python}" integration_tests.py -u "${USER}" -t "${LOCALHOST}"
stop_buzz
clear_cap

# deactivate virtual environment
deactivate
