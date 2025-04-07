# Unit Testing with scapy

## Usage

1. create and activate Python virtual environment (`--copies` required to make a
   copy of the Python interpreter that the test script sets capabilities on)
    ```bash
    python 3 -m venv --copies .venv
    source .venv/bin/activate
    ```

2. install dependencies
    ```bash
    pip install -r requirements.txt
    ```

3. run `sheriff-buzz` and test suite
    ```bash
    ./run_tests.sh
    ```

4. deactivate virtual environment when finished
    ```bash
    deactivate
    ```
