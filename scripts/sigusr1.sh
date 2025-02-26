#!/bin/bash

# send SIGUSR1 to running sheriff-buzz instance to get packet count stats
sudo kill -10 "$(pidof sheriff-buzz)"
