# Configuration

## Options

```json
{
        "packet_threshold": 5,
        "port_threshold": 100,
        "alert_threshold": 3,
        "action": "block",
        "redirect_ip": "0.0.0.0",
        "blacklist_ip": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
        "whitelist_ip": ["8.8.8.8", "100.100.100.100"],
        "blacklist_subnet": ["10.0.0.0/8", "1.2.3.0/24"],
        "whitelist_subnet": ["192.168.66.0/24"],
        "whitelist_port": [493, 12345],
        "dry_run": false,
        "test": false
}
```

| name | description |
| -- | -- |
| `packet_threshold` | number of packets before a flag-based alert |
| `port_threshold` | number of ports a source IP sends packets to before a port-based alert |
| `alert_threshold` | number of alerts produced for a given source IP before it is blacklisted |
| `action` | either `"block"` or `"redirect"` traffic from flagged IPs |
| `redirect_ip` | IP address to redirect to if `action` is set to `"redirect"` |
| `blacklist_ip` | list of IP addresses to blacklist |
| `whitelist_ip` | list of IP addresses to whitelist |
| `blacklist_subnet` | list of subnets (CIDR notation) to blacklist |
| `whitelist_subnet` | list of subnets (CIDR notation) to whitelist |
| `whitelist_port` | list of TCP ports to whitelist |
| `dry_run` | enable dry run mode |
| `test` | enable testing mode |

## Blacklist/Whitelist Precedence
- IP > subnet > port
- whitelist > blacklist
