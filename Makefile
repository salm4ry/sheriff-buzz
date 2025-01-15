############################################################
# eBPF makefile
# adapted from: https://github.com/w180112/ebpf_example
############################################################

######################################
# Set variable
######################################	

OS=$(shell lsb_release -si)
ARCH=$(shell uname -m | sed 's/x86_//;s/i[3-6]86/32/')
VER=$(shell lsb_release -sr)
INTERFACE=$(shell ip route show default | awk '{ print $$5 }')

# NOTE: need pkgconf installed
GLIB_CFLAGS = $(shell pkg-config --cflags glib-2.0)
GLIB_LIBS = $(shell pkg-config --libs glib-2.0)

CC = clang
INCLUDE += -I/usr/include/x86_64-linux-gnu

# include debug logging
CFLAGS = $(INCLUDE) $(GLIB_CFLAGS) -Wall -O2 -g -DDEBUG
# no debug logging
# CFLAGS = $(INCLUDE) $(GLIB_CFLAGS) -Wall -O2 -g

SRC_DIR = ./src

USR_TARGET = packet
USR_SRC = $(SRC_DIR)/packet.c

KRN_TARGET = $(SRC_DIR)/packet.bpf.o
KRN_SRC = $(SRC_DIR)/packet.bpf.c

USR_OBJ = $(USR_SRC:.c=.o)

all: $(KRN_TARGET) $(USR_TARGET)

######################################
# Compile & Link
# 	Must use \tab key after new line
######################################
$(KRN_TARGET): 
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	$(CC) $(CFLAGS) -target bpf -c $(KRN_SRC) -o $(KRN_TARGET)

$(USR_TARGET): $(USR_OBJ)
	$(CC) $(CFLAGS) $(USR_OBJ) -o $(USR_TARGET) -lbpf -lelf -lpq -lz -lcjson $(GLIB_LIBS)

######################################
# Unload
######################################
.PHONY: unload
unload:
	sudo ip link set $(INTERFACE) xdpgeneric off


######################################
# Run
######################################
.PHONY: run
run:
	sudo ./$(USR_TARGET) $(INTERFACE)

######################################
# Clean 
######################################
.PHONY: clean
clean:
	rm -f $(USR_TARGET)
	cd $(SRC_DIR) && rm -f *.o
