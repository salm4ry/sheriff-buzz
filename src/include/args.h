#ifndef __ARGS_INTERFACE
#define __ARGS_INTERFACE

#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>

struct args {
	char *config_file;
	char *log_file;
	char *bpf_obj_file;
	char *interface;
	bool skb_mode;
	bool dry_run;
	bool test;
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
    {"help", no_argument, NULL, 'h'},
	{"config", required_argument, NULL, 'c'},
	{"log", required_argument, NULL, 'l'},
	{"bpf-obj", required_argument, NULL, 'b'},
	{"skb-mode", no_argument, NULL, 's'},
	{"interface", required_argument, NULL, 'i'},
	{"address", required_argument, NULL, 'a'},
	{"dry-run", no_argument, NULL, 'd'},
	{"test", no_argument, NULL, 't'},
	/* terminate with zeroed struct */
	{NULL, 0, NULL, 0}
};

/**
 * Short options characters (followed by a colon = requires an argument)
 */
static char *short_opts = "c:l:si:b:dtha:";

static struct args default_args = {
	.config_file = "config/default.json",
	.log_file = "/var/log/sheriff-buzz.log",
	.bpf_obj_file = "src/sheriff-buzz.bpf.o",
	.skb_mode = false,
	.interface = NULL, /* interface is a required argument */
	.dry_run = false
};

char *addr_to_iface(char *address);
void set_default_args(struct args *args);
void usage(const char *prog_name);
void parse_args(int argc, char *argv[], struct args *args);

#endif
