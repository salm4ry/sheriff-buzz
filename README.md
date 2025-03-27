# `sheriff-buzz`: Intrusion Detection and Response with eBPF and XDP

## Table of Contents
1. [Dependencies](#dependencies)
2. [Alert Types](#alert-types)
3. [Logging](#logging)
4. [Configuration](#configuration)

## Dependencies

### Kernel

Linux kernel version 6.1+ required due to the user space ring buffer

*TODO: run on 6.1 kernel and make note of error- try to find minimum working
version*

### Compilation Tools
- `clang`
- `make`
- `pkg-config`
- `clang-tools` *(optional- for `scan-build`)*
- `python3-pygments` *(optional- for `pygmentize`)*

### Libraries
- `libglib2.0-dev`
- `libbpf-dev`
- `gcc-multilib`
- `libcjson-dev`
- `libpq-dev`

### Database
- `postgresql`

## Logging

The default log location is `/var/log/sheriff-buzz.log`.

## Configuration

All configuration is optional; defaults are in `./config/default.json` and an
example is in `./config/example_config.json`.

See [the config README](config/README.md) for option information

## Licensing

This project is licenseed under GNU GPL 2.0.
