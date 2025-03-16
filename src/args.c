#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include <ifaddrs.h>
#include <netdb.h>

#include "include/args.h"
#include "include/log.h"

/* get interface from address */
char *addr_to_iface(char *address)
{
	struct ifaddrs *current_iface, *ifaces;
	sa_family_t family;
	char iface_addr[NI_MAXHOST];
	int res;

	char *iface_name = NULL;

	if (getifaddrs(&ifaces) == -1) {
		perror("getifaddrs");
		exit(errno);
	}

	/* walk linked list of interfaces */
	current_iface = ifaces;
	while (current_iface) {
		family = current_iface->ifa_addr->sa_family;

		/* only consider IPv4 interfaces */
		if (family == AF_INET) {
			res = getnameinfo(current_iface->ifa_addr, sizeof(struct sockaddr_in),
					iface_addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (res != 0) {
				pr_err("getnameinfo failed: %s\n", gai_strerror(res));
				freeifaddrs(ifaces);
				exit(EXIT_FAILURE);
			}

			if (strncmp(iface_addr, address, NI_MAXHOST) == 0) {
				iface_name = malloc((strlen(current_iface->ifa_name)+1) * sizeof(char));
				if (!iface_name) {
					perror("memory allocation failed");
					freeifaddrs(ifaces);
					exit(errno);
				}

				/* copy interface name to be retunred */
				strncpy(iface_name, current_iface->ifa_name, strlen(current_iface->ifa_name)+1);
				break;
			}
		}

		current_iface = current_iface->ifa_next;
	}

	freeifaddrs(ifaces);
	return iface_name;
}

void set_default_args(struct args *args)
{
	args->config_file = default_args.config_file;
	args->log_file = default_args.log_file;
	args->bpf_obj_file = default_args.bpf_obj_file;
	args->skb_mode = default_args.skb_mode;
	args->dry_run = default_args.dry_run;
	args->interface = default_args.interface;
}

void print_usage(const char *prog_name)
{
	printf("usage: %s -i <interface> | -a <address> [<args>]\n", prog_name);
    printf("-i, --interface <name>: name of network interface to attach to\n");
    printf("-a, --address <address>: address of network interface to attach to\n");

	/* TODO config directory option */
    printf("-c, --config-file <filename>: name of config JSON file in ./config\n");

    printf("-l, --log-file <filename>: path to log file\n");
    printf("-b, --bpf-obj <path>: path to BPF object file\n");
    printf("-s, --skb-mode: enable SKB mode (use if native XDP not supported)\n");
    printf("-d, --dry-run: enable dry run mode\n");
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
				args->config_file = optarg;
				break;
			case 'l':
				/* log file path */
				args->log_file = optarg;
				break;
			case 's':
				args->skb_mode = true;
				break;
			case 'i':
				/* allocate memory for interface name (if not already obtained
				 * from -a) */
				if (!args->interface) {
					args->interface = malloc((strlen(optarg)+1) * sizeof(char));
						if (!args->interface) {
						perror("memory allocation failed");
						exit(EXIT_FAILURE);
					}

					/* copy interface name from arguments */
					strncpy(args->interface, optarg, strlen(optarg)+1);
				}
				break;
			case 'a':
				/* get interface for provided address (if not already obtained
				 * from -i) */
				if (!args->interface) {
					args->interface = addr_to_iface(optarg);
				}
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
