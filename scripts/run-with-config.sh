#!/bin/bash

dir="/home/$USER/sheriff-buzz"
prog=sheriff-buzz

# default interface
interface=$(ip route show default | awk '{ print $5 }')

# config file at config/config.json
config_file=config.json

# run with user-supplied config file
sudo "${dir}"/"${prog}" -i "${interface}" -c "${config_file}"
