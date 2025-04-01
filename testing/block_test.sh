#!/bin/bash

SSH=/usr/bin/ssh

export flags=('--syn')
export ports='1-200'
export src_ip='1.2.3.4'  # TODO randomise
export target='rex'

num_ports=100
config_file="~/sheriff-buzz/config.json"

run_on_host() {
	local ssh_opts=-q
	"${SSH}" "${ssh_opts}" "${target}" "$@"
}

# update config file on host
# blacklist after 1 port scan of 100 ports; 
# we're scanning 200 ports in order to see if our packets are blacklisted
run_on_host "echo \
'{
	\"packet_threshold\": 1,
	\"port_threshold\": ${num_ports},
	\"alert_threshold\": 1,
	\"action\": \"block\"
}' > ${config_file}"
