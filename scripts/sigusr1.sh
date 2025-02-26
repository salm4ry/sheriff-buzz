#!/bin/bash

# send SIGUSR1 to running sheriff-buzz instance to get packet count stats
sudo kill -USR1 "$(pidof sheriff-buzz)"
