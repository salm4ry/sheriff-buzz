#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>

#include "include/args.h"

void set_default_args(struct args *args)
{
	args->config = default_args.config;
	args->bpf_obj_file = default_args.bpf_obj_file;
	args->skb_mode = default_args.skb_mode;
	args->dry_run = default_args.dry_run;
}

void print_usage(const char *prog_name)
{
	printf("usage: %s -i <interface> [<args>]\n", prog_name);
    printf("-i, --interface <name>: name of network interface to attach to\n");
    printf("-c, --config <filename>: name of config JSON file in ./config\n");
    printf("-b, --bpf-obj <path>: path to BPF object file\n");
    printf("-s, --skb-mode: enable SKB mode\n");
    printf("-d, --dry-run: enable dry run mode\n");
	/* TODO usage for long + short options */
	/* TODO add also a -h|--help option
	 * that prints the usage and exits
	 */
}

void parse_args(int argc, char *argv[], struct args *args)
{
	int opt = 0, option_index = 0;

	set_default_args(args);

	while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
		switch (opt) {
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
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
				/* unrecognised argument: print usage and exit */
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}
}
