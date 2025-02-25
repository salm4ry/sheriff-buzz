# eBPF makefile
# adapted from: https://github.com/w180112/ebpf_example

# default route interface
INTERFACE=$(shell ip route show default | awk '{ print $$5 }')

# required for glib.h
GLIB_CFLAGS = $(shell pkg-config --cflags glib-2.0)
GLIB_LIBS = $(shell pkg-config --libs glib-2.0)

CC = clang
INCLUDE += -I/usr/include/x86_64-linux-gnu
LIBS = -lbpf -lelf -lpq -lz -lcjson -lresolv

CFLAGS_COMMON = -Wall -O2 -ggdb
CFLAGS_DEBUG=

# include debug logging if $DEBUG environment variable set to 1
ifeq ($(DEBUG), 1)
	CFLAGS_DEBUG = -DDEBUG
endif

CFLAGS = $(INCLUDE) $(GLIB_CFLAGS) $(CFLAGS_COMMON) $(CFLAGS_DEBUG)

TOP_DIR = $(PWD)/src
INCLUDE_DIR = $(TOP_DIR)/include

BASE_NAME = sheriff-buzz

TARGET = $(BASE_NAME)

# TODO fix
# SRC = $(wildcard $(TOP_DIR)/*.c)
SRC = $(TOP_DIR)/sheriff-buzz.c $(TOP_DIR)/log.c $(TOP_DIR)/parse_config.c \
	$(TOP_DIR)/parse_headers.c $(TOP_DIR)/args.c $(TOP_DIR)/bpf_load.c \
	$(TOP_DIR)/packet_data.c $(TOP_DIR)/detect_scan.c $(TOP_DIR)/time_conv.c

KTARGET = $(TOP_DIR)/$(BASE_NAME).bpf.o
KSRC = $(TOP_DIR)/$(BASE_NAME).bpf.c

all: $(KTARGET) $(TARGET)

# compile and link
# BPF: generate vmlinux.h then compile BPF object
# user space: compile program, tracking changes to includes
$(KTARGET): $(KSRC)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	$(CC) $(CFLAGS) -target bpf -c $(KSRC) -o $(KTARGET)

$(TARGET): $(SRC) $(INCLUDE_DIR)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS) $(GLIB_LIBS)

# unload
.PHONY: unload
unload:
	sudo ip link set $(INTERFACE) xdp off


# run (with default arguments and default route interface)
.PHONY: run
run:
	@ sudo ./$(TARGET) -i $(INTERFACE)

# clean
.PHONY: clean
clean:
	rm -f $(TARGET)
	cd $(TOP_DIR) && rm -f *.o

# get bpf_printk() output (only when compiled in debug mode)
.PHONY: bpf_debug
bpf_debug:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
