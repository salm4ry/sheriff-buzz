/// @file

#ifndef __BPF_LOAD_INTERFACE
#define __BPF_LOAD_INTERFACE

#include <stdio.h>
#include <bpf/libbpf.h>

/**
 * @struct uretprobe_opts
 * @brief init_uretprobe() arguments
 * @details Use to attach a uretprobe program that has a shared map (reuse the
 * file descriptor)
 */
struct uretprobe_opts {
	struct bpf_object **bpf_obj;  ///< BPF object (already loaded)
	const char *program_name;  ///< name of uretprobe program to attach
	const char *uprobe_func;  ///< name of user space function to attach to
	int bpf_map_fd;  ///< file descriptor of map to share
	const char *map_name;  ///< name of map to share
};

int init_xdp_prog(struct bpf_object **xdp_obj,
		const char *filename, const char *name, int ifindex, uint32_t flags,
		FILE *LOG);
int init_uretprobe(struct uretprobe_opts *args, FILE *LOG);

#endif
