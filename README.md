# `sheriff-buzz`: Port Scan Detection and Response with eBPF

## Table of Contents
- [Dependencies](#dependencies)
- [Setup](#setup)
- [Configuration](#configuration)
- [Documentation](#documentation)
- [Licensing](#licensing)

## Dependencies

### Linux kernel version

- Linux 6.3 or more recent
- or kernel with backport of upstream commit `6715df8d5d24 - bpf: Allow reads from uninit stack`

### Database
`postgresql`: tested with versions 15.12 and 17.4

### Development Packages

On a Debian-based system:

#### Compilation tools
- `clang`
- `make`
- `pkg-config`
- `clang-tools` *(optional- for `scan-build`)*
- `python3-pygments` *(optional- for `pygmentize`)*
- `doxygen` *(optional- for documentation generation)*

#### Libraries
- `libglib2.0-dev`
- `libbpf-dev`
- `gcc-multilib`
- `libcjson-dev`
- `libpq-dev`


## Setup

### Compilation
To compile `sheriff-buzz`, navigate to the root of the repository directory and
run:

```bash
$ make
```

#### Environment variables
- `DEBUG=1`: compile in debug mode
- `SCAN_BUILD=1`: perform compile-time static analysis with `scan-build`
- `V=1`: enable verbose mode

### Usage

`man` page:

```bash
$ make man
 ```


usage instructions:

```bash
$ sheriff-buzz --help
```

## Configuration

All configuration is optional:

- `config/default.json`: default config
- `config/example_config.json`: example configuration

See [the config README](config/README.md) for option information.

## Documentation

Produce documentation (HTML and LaTeX):

```bash
$ make docs
```

View the HTML documentation in a browser:

```bash
$ firefox doc/html/index.html
```

## Licensing

This project is licensed under GNU GPL 2.0.
