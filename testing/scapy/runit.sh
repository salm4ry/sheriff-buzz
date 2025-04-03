#!/bin/bash

dir="${HOME}/sheriff-buzz"
prog=sheriff-buzz
interface=lo
config_file="${dir}/config.json"
bpf_obj="${dir}/src/sheriff-buzz.bpf.o"

LOCALHOST=127.0.0.1

# run sheriff-buzz on loopback interface, setting config file location
echo "running ${prog}..."
sudo "${dir}/${prog}" -i "${interface}" -c "${config_file}" -b "${bpf_obj}" -t &

# run test suite
sudo ./.venv/bin/python3 run_tests.py -u "${USER}" -t "${LOCALHOST}"

sudo killall "${prog}"
