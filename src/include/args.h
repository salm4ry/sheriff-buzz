#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>

#include "bits/getopt_core.h"
#include "pr.h"

/**
 * Long options
 *
 * Defined as follows:
 *
 * struct option {
 *     const char *name; // long option name (option starts with two dashes)
 *     int has_arg;      // whether option takes an argument
 *     int *flag;        // how results are returned (val by default)
 *     int vall          // value to return/load into variable flag points to
 * }
 */
static struct option long_opts[] = {
	{"config", required_argument, 0, 'c'},
	{"bpf-obj", required_argument, 0, 'b'},
	{"skb-mode", no_argument, 0, 's'},
	{"interface", required_argument, 0, 'i'},
	/* terminate with zeroed struct */
	{0, 0, 0, 0}
};

struct args {
	char *config;
	char *bpf_obj_file;
	char *interface;
	bool skb_mode;
};

const struct args DEFAULT_ARGS = {
	.config = "config.json",
	.bpf_obj_file = "src/packet.bpf.o",
	.skb_mode = false,
	.interface = NULL /* interface is a required argument */
};

void set_default_args(struct args *args)
{
	args->config = DEFAULT_ARGS.config;
	args->bpf_obj_file = DEFAULT_ARGS.bpf_obj_file;
	args->skb_mode = DEFAULT_ARGS.skb_mode;
}

void print_usage(const char *prog_name)
{
	pr_err("usage: %s -i <interface>\n", prog_name);
	/* TODO usage for long + short options */
}

/**
 * Short options characters (followed by a colon = requires an argument)
 */
const char *short_opts = "c:si:b:";

/* TODO save argument values */
void parse_args(int argc, char *argv[], struct args *args)
{
	int opt = 0, option_index = 0;

	set_default_args(args);

	/* -1 = no more arguments to parse */
	while (1) {
		opt = getopt_long(argc, argv, short_opts, long_opts, &option_index);

		if (opt == -1)
			break;

		switch (opt) {
			case 'c':
				/* config file path */
				args->config = optarg;
				break;

			case 's':
				break;

			case 'i':
				args->interface = optarg;
				break;

			case 'b':
				args->bpf_obj_file = optarg;
				break;

			default:
				/* unrecognised argument */
				break;
		}
	}
}
