#include <stdio.h>
#include <stdlib.h>

#include <bpf/libbpf.h>

#include "log.h"

FILE *LOG;

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
		const char *filename, const char *name, int ifindex, uint32_t flags)
{
	int bpf_prog_fd = -1;
	int err = 0;

	struct bpf_program *xdp_prog;

	*xdp_obj = bpf_object__open_file(filename, NULL);
	if (*xdp_obj == NULL) {
		log_error("open object file failed: %s\n", strerror(errno));
		err = -errno;
		goto fail;
	}

	xdp_prog = bpf_object__find_program_by_name(*xdp_obj, name);
	if (xdp_prog == NULL) {
		log_error("find program in object failed: %s\n", strerror(errno));
		err = -errno;
		goto fail;
	}

	/* set to XDP */
	if (bpf_program__set_type(xdp_prog, BPF_PROG_TYPE_XDP) < 0) {
		log_error("set bpf type to xdp failed: %s\n", strerror(errno));
		err = -errno;
		goto fail;
	}

	if (bpf_object__load(*xdp_obj)) {
		log_error("load bpf object failed: %s\n", strerror(errno));
		err = -errno;
		goto fail;
	}

	bpf_prog_fd = bpf_program__fd(xdp_prog);
	if (bpf_prog_fd <= 0) {
		log_error("failed to load XDP program from file (%s): %s\n",
				filename, strerror(errno));
		err = -errno;
		goto fail;
	}

    err = bpf_xdp_attach(ifindex, bpf_prog_fd, flags, NULL);

fail:
	return err;
}

/**
 * Load and attach BPF uretprobe with a shared (already loaded) map
 *
 * uretprobe_obj: BPF object to load program into
 * filename: name of file BPF program is in
 * prog_name: name of BPF uretprobe program
 * uprobe_func: function to trace
 * map_fd: file descriptor of map to share
 * map_name: name of map to share
 */
int init_uretprobe(struct uretprobe_opts *args)
{
	int bpf_prog_fd = -1;
	int err = 0;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	struct bpf_program *uretprobe_prog;
	struct bpf_map *bpf_shared_map;

	*args->uretprobe_obj = bpf_object__open_file(args->filename, NULL);
	if (libbpf_get_error(args->uretprobe_obj)) {
		log_error("open object file failed: %s\n", strerror(errno));
		err = -errno;
		goto fail;
	}

	uretprobe_prog = bpf_object__find_program_by_name(*args->uretprobe_obj, args->program_name);
	if (uretprobe_prog == NULL) {
		log_error(msg, "find program in object failed: %s\n", strerror(errno));
		err = -errno;
		goto fail;
	}

    /* both XDP and uretprobe need to access the flagged_ips hash map (uretprobe
     * for writing, XDP for reading) so we reuse the file descriptor */
	bpf_shared_map = bpf_object__find_map_by_name(*args->uretprobe_obj, args->map_name);
	err = bpf_map__reuse_fd(bpf_shared_map, args->bpf_map_fd);
	if (err) {
		log_error("failed to reuse map fd: %s\n", strerror(errno));
		err = -errno;
		goto fail;
	}

	err = bpf_object__load(*args->uretprobe_obj);
	if (err) {
		log_error("load bpf object failed: %s\n", strerror(errno));
		err = -errno;
		goto fail;
	}

	bpf_prog_fd = bpf_program__fd(uretprobe_prog);
	if (!bpf_prog_fd) {
		log_error("failed to load bpf object file(%s) (%d): %s\n",
				args->filename, err, strerror(-err));
	}

	/* name of function to attach to */
	uprobe_opts.func_name = args->uprobe_func;
	/* uretprobe = attach to function exit (we want to read the ring buffer
	 * after we're done submitting) */
	uprobe_opts.retprobe = true;

	/* TODO: move to doc comment at the top */
	/* Attach BPF uprobe
     *
	 * prog: BPF program to attach
	 * pid: 0 for self (own process)
	 * binary_path: path to binary containing function symbol
	 * func_offset: offset within binary (set to 0 since we provided function
	 * 				name in uprobe_otps)
	 * opts: options
	 */
	if (!bpf_program__attach_uprobe_opts(uretprobe_prog, 0,
				"/proc/self/exe", 0, &uprobe_opts)) {
		log_error("uprobe attach failed: %s\n", strerror(errno));
	}

	return bpf_prog_fd;

fail:
	return err;
}
