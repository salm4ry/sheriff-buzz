#include <stdio.h>
#include <stdlib.h>

#include <bpf/libbpf.h>

#include "log.h"

FILE *LOG;

/* load XDP program */
int load_and_attach_xdp(struct bpf_object **xdp_obj,
		const char *filename, const char *progname, int ifindex, uint32_t flags)
{
	int prog_fd = -1;
	int err;

	struct bpf_program *prog;

	*xdp_obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(xdp_obj)) {
		log_error("open object file failed: %s\n", strerror(errno));
		return -1;
	}

	prog = bpf_object__find_program_by_name(*xdp_obj, progname);
	if (prog == NULL) {
		log_error("find program in object failed: %s\n", strerror(errno));
		return -1;
	}

	/* set to XDP */
	if (bpf_program__set_type(prog, BPF_PROG_TYPE_XDP) < 0) {
		log_error("set bpf type to xdp failed: %s\n", strerror(errno));
		return -1;
	}

	err = bpf_object__load(*xdp_obj);
	if (err) {
		log_error("load bpf object failed: %s\n", strerror(errno));
		return -1;
	}

	prog_fd = bpf_program__fd(prog);
	if (prog_fd <= 0) {
		log_error("failed to load XDP program from file (%s): %s\n",
				filename, strerror(errno));
		return -1;
	}

    err = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);

	return prog_fd;
}

/*
 * Load and attach BPF uretprobe with a shared (already loaded) map
 *
 * uretprobe_obj: BPF object to load program into
 * filename: name of file BPF program is in
 * prog_name: name of BPF uretprobe program
 * uprobe_func: function to trace
 * map_fd: file descriptor of map to share
 * map_name: name of map to share
 */
int load_and_attach_bpf_uretprobe(struct bpf_object **uretprobe_obj,
		const char *filename, const char *prog_name, const char *uprobe_func,
        int map_fd, char *map_name)
{
	int prog_fd = -1;
	int err;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	struct bpf_program *prog;
	struct bpf_map *shared_map;

	*uretprobe_obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(uretprobe_obj)) {
		log_error("open object file failed: %s\n", strerror(errno));
		return -1;
	}

	prog = bpf_object__find_program_by_name(*uretprobe_obj, prog_name);
	if (prog == NULL) {
		log_error(msg, "find program in object failed: %s\n", strerror(errno));
		return -1;
	}

    /* both XDP and uretprobe need to access the flagged_ips hash map (uretprobe
     * for writing, XDP for reading) so we reuse the file descriptor */
	shared_map = bpf_object__find_map_by_name(*uretprobe_obj, map_name);
	err = bpf_map__reuse_fd(shared_map, map_fd);
	if (err) {
		log_error("failed to reuse map fd: %s\n", strerror(errno));
		return -1;
	}

	err = bpf_object__load(*uretprobe_obj);
	if (err) {
		log_error("load bpf object failed: %s\n", strerror(errno));
		return -1;
	}

	prog_fd = bpf_program__fd(prog);
	if (!prog_fd) {
		log_error("failed to load bpf object file(%s) (%d): %s\n",
				filename, err, strerror(-err));
	}

	/* name of function to attach to */
	uprobe_opts.func_name = uprobe_func;
	/* uretprobe = attach to function exit (we want to read the ring buffer
	 * after we're done submitting) */
	uprobe_opts.retprobe = true;

	/* Attach BPF uprobe
     *
	 * prog: BPF program to attach
	 * pid: 0 for self (own process)
	 * binary_path: path to binary containing function symbol
	 * func_offset: offset within binary (set to 0 since we provided function
	 * 				name in uprobe_otps)
	 * opts: options
	 */
	if (!bpf_program__attach_uprobe_opts(prog, 0, 
				"/proc/self/exe", 0, &uprobe_opts)) {
		log_error("uprobe attach failed: %s\n", strerror(errno));
	}

	return prog_fd;
}
