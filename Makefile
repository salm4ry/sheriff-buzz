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
INTERFACE=enp10s0  # TODO find automated way of getting interface (differs between VM and container)

# NOTE need pkgconf installed
GLIB_CFLAGS = $(shell pkg-config --cflags glib-2.0)
GLIB_LIBS = $(shell pkg-config --libs glib-2.0)

CC = clang
INCLUDE += -I/usr/include/x86_64-linux-gnu
CFLAGS = $(INCLUDE) $(GLIB_CFLAGS) -Wall -O2 -g -DDEBUG  # NOTE debug mode
# CFLAGS = $(INCLUDE) $(GLIB_CFLAGS) -Wall -O2 -g

USR_TARGET = packet
USR_SRC = packet.c

KRN_TARGET = packet.bpf.o
KRN_SRC = packet.bpf.c

USR_OBJ = $(USR_SRC:.c=.o)

# SUBDIR = libbpf/src

# BUILDSUBDIR = $(SUBDIR:%=build-%)
# CLEANSUBDIR = $(SUBDIR:%=clean-%)

# all: $(BUILDSUBDIR) $(KRN_TARGET) $(USR_TARGET)
all: $(KRN_TARGET) $(USR_TARGET)

# $(BUILDSUBDIR):
#	${MAKE} -C $(@:build-%=%)

# .PHONY: $(BUILDSUBDIR)

######################################
# Compile & Link
# 	Must use \tab key after new line
######################################
$(KRN_TARGET): 
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	$(CC) $(CFLAGS) -target bpf -c $(KRN_SRC) -o $(KRN_TARGET)

$(USR_TARGET): $(USR_OBJ)
	$(CC) $(CFLAGS) $(USR_OBJ) -o $(USR_TARGET) -lbpf -lelf -lpq -lz $(GLIB_LIBS)
	# -lelf -lz libbpf/src/libbpf.a

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
clean: $(CLEANSUBDIR)
	rm -f $(USR_TARGET) *.o

$(CLEANSUBDIR):
	$(MAKE) -C  $(@:clean-%=%) clean
