#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

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

/**
 * Short options characters (followed by a colon = requires an argument)
 */
const char *short_opts = "c:si:b:";

/* TODO save argument values */
void parse_args(int argc, char *argv[])
{
	int c = 0, option_index = 0;

	/* -1 = no more arguments to parse */
	while (1) {
		c = getopt_long(argc, argv, short_opts, long_opts, &option_index);

		if (c == -1)
			break;

		switch (c) {
			case 'c':
				/* config file path */
				printf("config path: %s\n", optarg);
				break;

			case 's':
				printf("skb mode set\n");
				break;

			case 'i':
				printf("interface: %s\n", optarg);
				break;

			case 'b':
				printf("BPF object path: %s\n", optarg);
				break;

			case '?':
				break;

			default:
				printf("c = %d\n", c);
				break;
		}
	}
}
