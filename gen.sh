#!/bin/bash

# generate vmlinux.h (can use instead of Linux header files)
echo "generating vmlinux.h..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

error_code=$?
if [ $error_code -eq 0 ]; then
	echo "vmlinux.h generated successfully!"
fi
