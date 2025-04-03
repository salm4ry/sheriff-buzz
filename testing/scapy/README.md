# Unit Testing with scapy

## Usage

1. create and activate Python virtual environment
    ```bash
    python 3 -m venv .venv
    source .venv/bin/activate
    ```

2. install dependencies
    ```bash
    pip install -r requirements.txt
    ```

3. run `sheriff-buzz` and test suite
    ```bash
    ./runit.sh
    ```

4. deactivate virtual environment when finished
    ```bash
    deactivate
    ```

## Example Output


```bash
# runit.sh
running sheriff-buzz...
running tests...
copying config/block.json to ~/sheriff-buzz/config.json... done
10.10.188.146 -> 127.0.0.1, ports: (1, 100)
10.10.188.146 -> 127.0.0.1, ports: [12345]
looking up BPF test_results[2461796874]...
block: XDP_DROP -> PASS

copying config/redirect.json to ~/sheriff-buzz/config.json... done
10.10.188.97 -> 127.0.0.1, ports: (1, 100)
10.10.188.97 -> 127.0.0.1, ports: [12345]
looking up BPF test_results[1639713290]...
redirect: XDP_TX -> PASS

copying config/bw_precedence.json to ~/sheriff-buzz/config.json... done
10.10.66.66 -> 127.0.0.1, ports: [12345]
looking up BPF test_results[1111624202]...
bw_precedence: XDP_DROP -> PASS

copying config/wb_precedence.json to ~/sheriff-buzz/config.json... done
10.10.77.77 -> 127.0.0.1, ports: [12345]
looking up BPF test_results[1296894474]...
wb_precedence: XDP_PASS -> PASS

tests complete!
```
