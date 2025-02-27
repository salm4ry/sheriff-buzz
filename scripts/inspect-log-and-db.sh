#!/bin/bash

LS=/usr/bin/ls
HEAD=/usr/bin/head

root_dir="$HOME/sheriff-buzz"
log_dir="$root_dir"/log
db_name="sheriff_logbook"

# get 5 most recent alerts
LOG_QUERY="SELECT * FROM scan_alerts INNER JOIN alert_type 
	   ON scan_alerts.alert_type = alert_type.id 
	   ORDER BY latest DESC FETCH NEXT 5 ROWS ONLY;"

get_log_file () {
	local LS_OPTS='-1t'
	local HEAD_OPTS='-1'
	printf "%s" "$(${LS} ${LS_OPTS} ${log_dir} | ${HEAD} ${HEAD_OPTS})"
}

check_log() {
	current_count=$1
	log=$2
	new_count=$(grep -c 'alert:' "$log_dir/$log")
	return $(( new_count > current_count ))
}

count_alerts() {
	log=$1

	# count alert log lines
	grep -c 'alert:' "$log_dir/$log"
}

# get log filename (assumption that sheriff-buzz is already running
log=$(get_log_file)


while true
do
	current_count=$(count_alerts "$log")

	# wait until alert has made it into the log file before continuing
	printf "current alert count: %d\n" "$current_count"
	printf "waiting for logged alert in %s...\n" "$log"
	while true
	do
		# check if number of alerts in log file has changed
		if check_log "$current_count" "$log"
		then
			sleep 1
		else
			break
		fi
	done
	# get 5 most recent alert log lines
	tac "${log_dir}/${log}" | grep -m5 'alert:'

	# output database lines (without pager)
	PAGER='' psql "${db_name}" -c "${LOG_QUERY}"
done
