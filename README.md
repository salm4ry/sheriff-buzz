# Intrusion Detection and Response with eBPF and XDP

## Table of Contents
1. [Dependencies](#dependencies)
2. [Alert Types](#alert-types)
3. [Configuration](#configuration)

## Dependencies

### Kernel

Linux kernel version 6.1+ required due to the user space ring buffer

*TODO: run on 6.1 kernel and make note of error- try to find minimum working
version*

### Compilation Tools
- `clang`
- `make`
- `pkg-config`
- `bpftool`

### Libraries
- `libglib2.0-dev`
- `libbpf-dev`
- `gcc-multilib`
- `libcjson-dev`
- `libpq-dev`

### Database
- `postgresql`

## Alert Types

## Configuration

Configuration is stored in `./config/config.json`

```json
{
        "packet_threshold": 5,
        "port_threshold": 100,
        "flag_threshold": 3,
        "action": "block",
        "redirect_ip": "0.0.0.0"
        "blacklist_ip": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
        "whitelist_ip": ["8.8.8.8", "100.100.100.100"]
        "blacklist_subnet": ["10.0.0.0/8", "1.2.3.0/24"],
        "whitelist_subnet": ["192.168.66.0/24"]
}
```

### Defaults
All configuration is optional; defaults are in `./config/default.json`

### Options

- `packet_threshold`: minimum number of packets required to trigger a flag-based
  alert
- `port_threshold`: number of ports a source IP must send packets to in order to
  trigger a port-based alert
- `flag_threshold`: number of alerts produced for a given source IP before it is
  flagged
- `action`: either `"block"` or `"redirect"` flagged IPs to `redirect_ip`
- `blacklist_ip`, `blacklist_subnet`: perform the specified action on these IPs
  and subnets
- `whitelist_ip`, `whitelist_subnet`: do not analyse traffic on these IPs and
  subnets

#### Blacklist/Whitelist Precedence
- IP > subnet
- whitelist > blacklist
