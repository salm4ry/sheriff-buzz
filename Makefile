# eBPF makefile
# adapted from: https://github.com/w180112/ebpf_example

# default route interface
interface=$(shell ip route show default | awk '{ print $$5 }')

ifeq ($(SCAN_BUILD),1)
	CC := scan-build clang
else
	CC := clang
endif

INCLUDE += -I/usr/include/x86_64-linux-gnu
LIBS = -lbpf -lelf -lpq -lz -lcjson -lresolv

GLIB_CFLAGS = $(shell pkg-config --cflags glib-2.0)
GLIB_LIBS = $(shell pkg-config --libs glib-2.0)

CFLAGS_COMMON = -Wall -O2 -ggdb

# enable debug logging if DEBUG environment variable set to 1
ifeq ($(DEBUG), 1)
	CFLAGS_DEBUG := -DDEBUG
else
	CFLAGS_DEBUG :=
endif

ifeq ($(TEST), 1)
	CFLAGS_DEBUG += -DTEST
endif

CFLAGS = $(INCLUDE) $(GLIB_CFLAGS) $(CFLAGS_COMMON) $(CFLAGS_DEBUG)


BASENAME = sheriff-buzz

top_dir = $(PWD)/src
include_dir = $(top_dir)/include

target = $(BASENAME)
ktarget = $(top_dir)/$(BASENAME).bpf.o

#
# user-space source files: all .c files except .bpf.c ones
#
src = $(filter-out $(top_dir)/%.bpf.c, $(wildcard $(top_dir)/*.c))

# BPF source code: .bpf.c
ksrc = $(top_dir)/$(BASENAME).bpf.c

all: $(ktarget) $(target)

# build BPF object
# V=1 verbose, quiet otherwise
$(ktarget): $(ksrc)
ifeq ($(V),1)
	$(CC) $(CFLAGS) -target bpf -c $(ksrc) -o $(ktarget)
else
	@$(CC) $(CFLAGS) -target bpf -c $(ksrc) -o $(ktarget)
endif

#
# build user space program
# V=1 verbose, quiet otherwise
#
$(target): $(src) $(include_dir)
ifeq ($(V),1)
	$(CC) $(CFLAGS) $(src) -o $(target) $(LIBS) $(GLIB_LIBS)
else
	@$(CC) $(CFLAGS) $(src) -o $(target) $(LIBS) $(GLIB_LIBS)
endif

#
# unload, needed in case the program terminates unexpectedly
# and fails to clean up after itself
#
.PHONY: unload
unload:
	@sudo ip link set $(interface) xdp off

#
# run (with default arguments and default route interface)
#
.PHONY: run
run:
	@sudo ./$(target) -i $(interface)

.PHONY: clean
clean:
	@rm -f $(target)
	@cd $(top_dir) && rm -f *.o
#
# bpf_printk() output (available only with debug build)
#
.PHONY: bpf_debug
bpf_debug:
	@sudo cat /sys/kernel/debug/tracing/trace_pipe

.PHONY: bpf_objdump
bpf_objdump:
ifeq ($(SYN_HLT),1)
	@llvm-objdump --demangle --disassemble  $(ktarget) | pygmentize -l gas -O style=monokai
else
	@llvm-objdump -d $(ktarget)
endif
