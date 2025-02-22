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

SRC_DIR = ./src
INCLUDE_DIR = $(SRC_DIR)/include

USR_TARGET = packet
USR_SRC = $(SRC_DIR)/packet.c

KRN_TARGET = $(SRC_DIR)/packet.bpf.o
KRN_SRC = $(SRC_DIR)/packet.bpf.c

USR_OBJ = $(USR_SRC:.c=.o)

all: $(KRN_TARGET) $(USR_TARGET)

# compile and link
# BPF: generate vmlinux.h then compile BPF object
# user space: compile program, tracking changes to includes
$(KRN_TARGET): $(KRN_SRC)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	$(CC) $(CFLAGS) -target bpf -c $(KRN_SRC) -o $(KRN_TARGET)

$(USR_OBJ): $(INCLUDE_DIR)
$(USR_TARGET): $(USR_OBJ) $(INCLUDE_DIR)
	$(CC) $(CFLAGS) $(USR_OBJ) -o $(USR_TARGET) $(LIBS) $(GLIB_LIBS)
# unload
.PHONY: unload
unload:
	sudo ip link set $(INTERFACE) xdp off


# run (with default arguments and default route interface)
.PHONY: run
run:
	@ sudo ./$(USR_TARGET) -i $(INTERFACE)

# clean
.PHONY: clean
clean:
	rm -f $(USR_TARGET)
	cd $(SRC_DIR) && rm -f *.o

# get bpf_printk() output (only when compiled in debug mode)
.PHONY: bpf_debug
bpf_debug:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
