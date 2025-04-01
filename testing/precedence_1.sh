#!/bin/bash

SSH=/usr/bin/ssh

export flags=('--syn')
export ports='1-200'
export src_ip='9.9.9.9'  # TODO randomise
export target='rex'

num_ports=100
config_file="~/sheriff-buzz/config.json"
subnet='9.9.9.9/24'

run_on_host() {
	local ssh_opts=-q
	"${SSH}" "${ssh_opts}" "${target}" "$@"
}

# test precedence: blacklisted IP > whitelisted subnet
run_on_host "echo \
'{
	\"packet_threshold\": 1,
	\"port_threshold\": ${num_ports},
	\"alert_threshold\": 1,
	\"blacklist_ip\": [\"${src_ip}\"],
	\"whitelist_subnet\": [\"${subnet}\"]
}' > ${config_file}"
