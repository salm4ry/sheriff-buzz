#!/bin/bash

LOCALHOST=127.0.0.1

sudo ./.venv/bin/python3 run_tests.py -u "${USER}" -t "${LOCALHOST}"
