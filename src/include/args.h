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
	{"dry-run", no_argument, 0, 'd'},
	/* terminate with zeroed struct */
	{0, 0, 0, 0}
};

struct args {
	char *config;
	char *bpf_obj_file;
	char *interface;
	bool skb_mode;
	bool dry_run;
};

const struct args DEFAULT_ARGS = {
	.config = "default.json",
	.bpf_obj_file = "src/sheriff-buzz.bpf.o",
	.skb_mode = false,
	.interface = NULL, /* interface is a required argument */
	.dry_run = false
};

void set_default_args(struct args *args)
{
	args->config = DEFAULT_ARGS.config;
	args->bpf_obj_file = DEFAULT_ARGS.bpf_obj_file;
	args->skb_mode = DEFAULT_ARGS.skb_mode;
	args->dry_run = DEFAULT_ARGS.dry_run;
}

void print_usage(const char *prog_name)
{
	printf("usage: %s -i <interface>\n", prog_name);
	/* TODO usage for long + short options */
	/* TODO add also a -h|--help option
	 * that prints the usage and exits
	 */
}

/**
 * Short options characters (followed by a colon = requires an argument)
 */
const char *short_opts = "c:si:b:d";

void parse_args(int argc, char *argv[], struct args *args)
{
	int opt = 0, option_index = 0;

	set_default_args(args);

	while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
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
			case 'd':
				args->dry_run = true;
				break;
			default:
				/* unrecognised argument */
				/* print a message about it
				 * so that the user doesn't
				 * keep repeating the same syntax
				 * error
				 */
				print_usage(argv[0]);
				exit(1);
		}
	}
}
