#!/bin/bash

dir="/${HOME}/sheriff-buzz"
prog=sheriff-buzz

# attach to loopback since we're testing on the same machine
interface=lo

# config file at config.json
config_file="${dir}"/config.json

# run with user-supplied config file
# enable testing on default test subnet (10.10.10.0/16) with -t
sudo "${dir}"/"${prog}" -i "${interface}" -c "${config_file}"
