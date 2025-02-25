#ifndef __BPF_LOAD_INTERFACE
#define __BPF_LOAD_INTERFACE

#include <stdio.h>
#include <bpf/libbpf.h>

struct uretprobe_opts {
	struct bpf_object **uretprobe_obj;
	const char *filename;
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
