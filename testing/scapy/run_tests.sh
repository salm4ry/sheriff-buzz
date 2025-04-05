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
capabilities='CAP_NET_RAW,CAP_DAC_OVERRIDE=+ep'

LOCALHOST=127.0.0.1

# run sheriff-buzz on loopback interface, setting config file location
echo "running ${prog}..."
sudo -b "${dir}/${prog}" -i "${interface}" -c "${config_file}" -b "${bpf_obj}" -t

# activate virtual environment
# (follow instructions in README.md to create the .venv directory)
source "${venv_dir}"/bin/activate

# set capabilities so tests don't have to run as root
sudo setcap "${capabilities}" "${venv_python}"

getcap "${venv_python}"
# run test suite
"${venv_python}" unit_tests.py -u "${USER}" -t "${LOCALHOST}"

sudo killall "${prog}"
