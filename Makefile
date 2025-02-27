# eBPF makefile
# adapted from: https://github.com/w180112/ebpf_example

# default route interface
interface=$(shell ip route show default | awk '{ print $$5 }')

CC = clang
INCLUDE += -I/usr/include/x86_64-linux-gnu
LIBS = -lbpf -lelf -lpq -lz -lcjson -lresolv

GLIB_CFLAGS = $(shell pkg-config --cflags glib-2.0)
GLIB_LIBS = $(shell pkg-config --libs glib-2.0)

CFLAGS_COMMON = -Wall -O2 -ggdb
CFLAGS_DEBUG=

# include debug logging if $DEBUG environment variable set to 1
ifeq ($(DEBUG), 1)
	CFLAGS_DEBUG = -DDEBUG
endif

CFLAGS = $(INCLUDE) $(GLIB_CFLAGS) $(CFLAGS_COMMON) $(CFLAGS_DEBUG)

top_dir = $(PWD)/src
include_dir = $(top_dir)/include

BASE_NAME = sheriff-buzz

target = $(BASE_NAME)
ktarget = $(top_dir)/$(BASE_NAME).bpf.o

# TODO fix
# src = $(wildcard $(top_dir)/*.c) doesn't work since we have a .bpf.c file ->
# move to different directory?
src = $(top_dir)/sheriff-buzz.c $(top_dir)/log.c $(top_dir)/parse_config.c \
	$(top_dir)/parse_headers.c $(top_dir)/args.c $(top_dir)/bpf_load.c \
	$(top_dir)/packet_data.c $(top_dir)/detect_scan.c $(top_dir)/time_conv.c

ksrc = $(top_dir)/$(BASE_NAME).bpf.c

all: $(ktarget) $(target)

# compile and link
# BPF: generate vmlinux.h then compile BPF object
# user space: compile program, tracking changes to includes
$(ktarget): $(ksrc)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	$(CC) $(CFLAGS) -target bpf -c $(ksrc) -o $(ktarget)

$(target): $(src) $(include_dir)
	$(CC) $(CFLAGS) $(src) -o $(target) $(LIBS) $(GLIB_LIBS)

# unload
.PHONY: unload
unload:
	sudo ip link set $(interface) xdp off


# run (with default arguments and default route interface)
.PHONY: run
run:
	@ sudo ./$(target) -i $(interface)

# clean
.PHONY: clean
clean:
	rm -f $(target)
	cd $(top_dir) && rm -f *.o

# get bpf_printk() output (only when compiled in debug mode)
.PHONY: bpf_debug
bpf_debug:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
