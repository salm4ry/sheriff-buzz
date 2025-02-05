#!/bin/bash

PACKET_THRESHOLD=${1:-5}
PORT_NUM=493

# Xmas scan
for ((i=0; i<"$PACKET_THRESHOLD"; i++)); do
	sudo nmap -sX -p $PORT_NUM
done

# FIN scan
for ((i=0; i<"$PACKET_THRESHOLD"; i++)); do
	sudo nmap -sF -p $PORT_NUM
done

# NULL scan
for ((i=0; i<"$PACKET_THRESHOLD"; i++)); do
	sudo nmap -sN -p $PORT_NUM
done
