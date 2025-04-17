# Configuration

## Options

| name | description |
| -- | -- |
| `packet_threshold` | minimum number of packets to trigger a flag-based alert |
| `port_threshold` | minimum number of ports probed by an IP to trigger a port-based alert |
| `alert_threshold` | minimum number of alerts that warrant blacklisting of an IP |
| `action` | either `"block"` or `"redirect"` traffic from flagged IPs |
| `redirect_ip` | IP address to redirect to |
| `blacklist_ip` | list of IP addresses to blacklist |
| `whitelist_ip` | list of IP addresses to whitelist |
| `blacklist_subnet` | list of subnets (CIDR notation) to blacklist |
| `whitelist_subnet` | list of subnets (CIDR notation) to whitelist |
| `whitelist_port` | list of TCP ports to whitelist |
| `dry_run` | toggle dry run mode |
| `test` | toggle testing mode |

### Example

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

## Blacklist/Whitelist Precedence
- IP > subnet > port
- whitelist > blacklist
