#ifndef __ARGS_INTERFACE
#define __ARGS_INTERFACE

#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>

struct args {
	char *config;
	char *bpf_obj_file;
	char *interface;
	bool skb_mode;
	bool dry_run;
};

/**
 * Long options
 *
 * Defined as follows:
 *
 * struct option {
 *     const char *name; // long option name (option starts with two dashes)
 *     int has_arg;      // whether option takes an argument
 *     int *flag;        // how results are returned (val by default)
 *     int val;          // value to return/load into variable flag points to
 * }
 */
static struct option long_opts[] = {
    {"help", no_argument, 0, 'h'},
	{"config", required_argument, 0, 'c'},
	{"bpf-obj", required_argument, 0, 'b'},
	{"skb-mode", no_argument, 0, 's'},
	{"interface", required_argument, 0, 'i'},
	{"dry-run", no_argument, 0, 'd'},
	/* terminate with zeroed struct */
	{0, 0, 0, 0}
};

static struct args default_args = {
	.config = "default.json",
	.bpf_obj_file = "src/sheriff-buzz.bpf.o",
	.skb_mode = false,
	.interface = NULL, /* interface is a required argument */
	.dry_run = false
};

void set_default_args(struct args *args);
void print_usage(const char *prog_name);
void parse_args(int argc, char *argv[], struct args *args);

#endif
