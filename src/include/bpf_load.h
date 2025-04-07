#ifndef __BPF_LOAD_INTERFACE
#define __BPF_LOAD_INTERFACE

#include <stdio.h>
#include <bpf/libbpf.h>

/*
 * bpf_obj: BPF object (already loaded into the kernel)
 * program_name: name of program to attach
 * prog_name: name of uretprobe program
 * map_fd: file descriptor of map to share
 * map_name: name of map to share
 */
struct uretprobe_opts {
	struct bpf_object **bpf_obj;
	const char *program_name;
	const char *uprobe_func;
	int bpf_map_fd;
	const char *map_name;
};

/* TODO make these a struct of functions (see bpf_map_ops in the kernel) */

/* load XDP program */
int init_xdp_prog(struct bpf_object **xdp_obj,
		const char *filename, const char *name, int ifindex, uint32_t flags,
		FILE *LOG);
int init_uretprobe(struct uretprobe_opts *args, FILE *LOG);

#endif
