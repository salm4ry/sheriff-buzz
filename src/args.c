/// @file

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <libgen.h>

#include <ifaddrs.h>
#include <netdb.h>

#include "include/args.h"
#include "include/log.h"

/**
 * @brief Get network interface name from address
 * @param address address of network interface
 * @return interface name on success, NULL on error
 */
char *addr_to_iface(char *address)
{
	struct ifaddrs *current_iface, *ifaces;
	sa_family_t family;
	char iface_addr[NI_MAXHOST];
	int res;

	char *iface_name = NULL;

	if (getifaddrs(&ifaces) == -1) {
		p_error("getifaddrs failed");
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
					p_error("failed to allocate iface_name");
					freeifaddrs(ifaces);
					exit(errno);
				}

				/* copy interface name to be returned */
				strncpy(iface_name, current_iface->ifa_name, strlen(current_iface->ifa_name)+1);
				break;
			}
		}

		current_iface = current_iface->ifa_next;
	}

	freeifaddrs(ifaces);
	return iface_name;
}

/**
 * @brief Set default command-line argument values
 * @param args argument structure to set values of
 */
void set_default_args(struct args *args)
{
	args->config_file = default_args.config_file;
	args->log_file = default_args.log_file;
	args->bpf_obj_file = default_args.bpf_obj_file;
	args->skb_mode = default_args.skb_mode;
	args->dry_run = default_args.dry_run;
	args->test = default_args.test;
	args->interface = default_args.interface;
}

/**
 * @brief Print usage
 * @param prog_name name of executable (argv[0])
 */
void usage(char *prog_name)
{
	printf("usage: %s -i <interface> | -a <address> [<args>]\n",
			basename(prog_name));
	printf("-i, --interface <name>: name of network interface to attach to\n"
	       "-a, --address <address>: address of network interface to attach to\n"
	       "-c, --config <filename>: path to config file\n"
	       "-l, --log <filename>: path to log file\n"
	       "-b, --bpf-obj <path>: path to BPF object file\n"
	       "-s, --skb-mode: enable SKB mode (use if native XDP not supported)\n"
	       "-d, --dry-run: enable dry run mode\n"
	       "-t, --test: enable testing mode\n"
	       "-h, --help: print this message and exit\n");
}

/**
 * @brief Parse command-line arguments
 * @param argc argument count
 * @param argv argument vector
 * @param args argument structure to store results
 */
void parse_args(int argc, char *argv[], struct args *args)
{
	int opt = 0, option_index = 0;

	set_default_args(args);

	while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
		switch (opt) {
		case 'h':
			usage(basename(argv[0]));
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
			/* allocate memory for interface name (if not already obtained from -a) */
			if (!args->interface) {
				args->interface = malloc((strlen(optarg)+1) * sizeof(char));
					if (!args->interface) {
						p_error("Failed to allocate interface");
						exit(errno);
					}

				/* copy interface name from arguments */
				strncpy(args->interface, optarg, strlen(optarg)+1);
			} else {
				printf("interface already set, ignoring -i\n");
				/* TODO should we exit with an error or continue? */
			}
			break;
		case 'a':
			/* set interface for provided address if not already set
			 * addr_to_iface() is responsible for all the error handing
			 */
			if (!args->interface) {
				args->interface = addr_to_iface(optarg);
			} else {
				printf("interface already set, ignoring -a\n");
				/* TODO should we exit with an error or continue? */
			}

			if (!args->interface) {
				/* we get here if we fail to find an interface that matches
				 * the user provided IP address
				 */
				printf("no interface found with address %s\n",
						optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'b':
			args->bpf_obj_file = optarg;
			break;
		case 'd':
			args->dry_run = true;
			break;
		case 't':
			args->test = true;
			break;
		default:
			/* invalid argument: print usage and exit */
			usage(basename(argv[0]));
			exit(EXIT_FAILURE);
		}
	}
}
