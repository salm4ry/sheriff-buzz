#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

/*
 * Long options start with two dashes and are defined as follows:
 *
 * struct option {
 *     const char *name; // long option name
 *     int has_arg;      // whether option takes an argument
 *     int *flag;        // how results are returned
 *     int val;          // value to return/load into variable flag points to
 * }
 */

int main(int argc, char *argv[])
{
	int c = 0;
	int option_index = 0;

	static struct option long_opts[] = {
		{"config-file", required_argument, 0, 'c'},
		{"bpf-file", required_argument, 0, 'b'},
		{"skb-mode", no_argument, 0, 's'},
		{"interface", required_argument, 0, 'i'},
		/* terminate with zeroed struct */
		{0, 0, 0, 0}
	};

	/* short option characters
	 * followed by a colon = requires an argument */
	const char *short_opts = "c:si:b:";

	/* -1 = no more arguments to parse */
	while (c != -1) {
		c = getopt_long(argc, argv, short_opts, long_opts, &option_index);

		if (c == -1)
			break;

		switch (c) {
			case 0:
				/* long options with val unset */
				printf("option %s", long_opts[option_index].name);
				if (optarg)
					printf(" with arg %s", optarg);
				printf("\n");
				break;

			case 'c':
				printf("config path: %s\n", optarg);
				break;

			case 's':
				printf("skb mode set\n");
				break;

			case 'i':
				printf("interface: %s\n", optarg);
				break;

			case 'b':
				printf("BPF path: %s\n", optarg);
		}
	}


	return EXIT_SUCCESS;
}
