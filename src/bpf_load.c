/// @file

#include <stdio.h>
#include <errno.h>

#include <bpf/libbpf.h>

#include "include/bpf_load.h"
#include "include/log.h"

/**
 * @brief Load and attach XDP program
 * @param bpf_obj BPF object containing the XDP program
 * @param filename file to load the BPF object from
 * @param name XDP program nmae
 * @param ifindex network interface index
 * @param flags XDP flags
 * @param LOG log file to write errors to
 * @return 0 on success, negative error code on failure
 */
int init_xdp_prog(struct bpf_object **bpf_obj,
		const char *filename, const char *name, int ifindex, uint32_t flags,
		FILE *LOG)
{
	int bpf_prog_fd = -1;
	int err = 0;

	struct bpf_program *xdp_prog;

	/* returns NULL on error, error stored in errno */
	*bpf_obj = bpf_object__open_file(filename, NULL);
	if (*bpf_obj == NULL) {
		log_error(LOG, "open object file failed: %s\n", strerror(errno));
		err = -errno;
		goto fail;
	}

	/* returns NULL on error */
	xdp_prog = bpf_object__find_program_by_name(*bpf_obj, name);
	if (xdp_prog == NULL) {
		log_error(LOG, "find program in object failed: %s\n", strerror(err));
		err = -errno;
		goto fail;
	}

	/* set program type to XDP, returns non-zero on error */
	if (bpf_program__set_type(xdp_prog, BPF_PROG_TYPE_XDP) != 0) {
		log_error(LOG, "set bpf type to xdp failed: %s\n", strerror(err));
		err = -errno;
		goto fail;
	}

	/* returns 0 on success, negative error code otherwise (error code
	 * stored in errno) */
	err = bpf_object__load(*bpf_obj);
	if (err < 0) {
		log_error(LOG, "load bpf object failed: %s\n", strerror(errno));
		err = -errno;
		goto fail;
	}

	/* returns negative error code on failure */
	bpf_prog_fd = bpf_program__fd(xdp_prog);
	if (bpf_prog_fd < 0) {
		log_error(LOG, "failed to get XDP program %s fd: %d\n",
				name, bpf_prog_fd);
		err = bpf_prog_fd;
		goto fail;
	}

	/* negative error code on failure */
	err = bpf_xdp_attach(ifindex, bpf_prog_fd, flags, NULL);

fail:
	return err;
}

/**
 * @brief Load and attach BPF uretprobe with a shared (already loaded) map
 * @param bpf_obj BPF object to load program into
 * @param prog_name name of BPF uretprobe program
 * @param uprobe_func function to trace
 * @param map_fd file descriptor of map to share
 * @param map_name: name of map to share
 * @return 0 on success, negative error code on failure
 */
int init_uretprobe(struct uretprobe_opts *args, FILE *LOG)
{
	int err = 0;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	struct bpf_program *uretprobe_prog;
	struct bpf_map *bpf_shared_map;

	uretprobe_prog = bpf_object__find_program_by_name(*args->bpf_obj, args->program_name);
	if (uretprobe_prog == NULL) {
		log_error(LOG, "find program in object failed: %s\n", strerror(errno));
		err = -errno;
		goto fail;
	}

	bpf_shared_map = bpf_object__find_map_by_name(*args->bpf_obj, args->map_name);
	if (!bpf_shared_map) {
		log_error(LOG, "failed to find map %s: %s\n",
				args->map_name, strerror(errno));
		err = -1;
		goto fail;
	}


	/* both XDP and uretprobe programs need to access the shared hash map
	 * (one for writing, one for reading) so we reuse the file descriptor
	 *
	 * returns negative error code on failure */
	err = bpf_map__reuse_fd(bpf_shared_map, args->bpf_map_fd);
	if (err < 0) {
		log_error(LOG, "failed to reuse map fd: %s\n", strerror(err));
		goto fail;
	}

	/* returns negative error code on failure */
	err = bpf_program__fd(uretprobe_prog);
	if (err < 0) {
		log_error(LOG, "failed to get BPF program %s fd: %d\n",
				args->program_name, strerror(err));
		goto fail;
	}

	/* name of function to attach to */
	uprobe_opts.func_name = args->uprobe_func;
	/* uretprobe = attach to function exit (we want to read the ring buffer
	 * after we're done submitting) */
	uprobe_opts.retprobe = true;

	/*
	 * attach BPF uprobe (returns NULL on error and sets errno)
	 *
	 * uretprobe_prog: name of program
	 * 0: PID (0 for self)
	 * /proc/self/exe: path to binary containing function symbol
	 * 0: offset within binary (set to 0 since we function name is in opts)
	 * uprobe_opts: options
	 */
	if (!bpf_program__attach_uprobe_opts(uretprobe_prog, 0,
				"/proc/self/exe", 0, &uprobe_opts)) {
		log_error(LOG, "uprobe attach failed: %s\n", strerror(errno));
		err = -errno;
		goto fail;
	}

	return err;

fail:
	return err;
}
