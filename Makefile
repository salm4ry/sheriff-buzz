############################################################
# ebpf example makefile
# source: https://github.com/w180112/ebpf_example
############################################################

######################################
# Set variable
######################################	

OS=$(shell lsb_release -si)
ARCH=$(shell uname -m | sed 's/x86_//;s/i[3-6]86/32/')
VER=$(shell lsb_release -sr)
INTERFACE=enp10s0  # TODO find automated way of getting interface (differs between VM and container)

CC = clang
INCLUDE += -I/usr/include/x86_64-linux-gnu
CFLAGS = $(INCLUDE) -Wall -O2 -g

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
	$(CC) $(CFLAGS) $(USR_OBJ) -o $(USR_TARGET) -lbpf -lelf -lpq -lz
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
