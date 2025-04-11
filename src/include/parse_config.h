/// @file

#ifndef __CONFIG_INTERFACE
#define __CONFIG_INTERFACE

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#include <pthread.h>
#include <unistd.h>
#include <poll.h>
#include <sys/inotify.h>

/**
 * @brief
 * maximum number of IPs allowed from the config file
 * (256 blacklist and 256 whitelist)
 */
#define MAX_IP_LIST 256

#define MAX_SUBNET_LIST 128  ///< maximum subnet list size (matches BPF map)
#define MAX_PORT_LIST 1024   ///< maximum port list size (matches BPF map)

#define MAX_PACKET_THRESHOLD 1000  ///< maximum allowed packet threshold
#define MAX_PORT_THRESHOLD 65536  ///< maximum allowed port threshold
#define MAX_ALERT_THRESHOLD 10  ///< maximum allowed alert threshold

#define MIN_PORT 0  ///< minimum port value
#define MAX_PORT 65535  ///< maximum port value

#define REDIRECT 0  ///< redirect blacklisted traffic
#define BLOCK 1  ///< block blacklisted traffic

#define UNDEFINED -1  ///< undefined config option

#define MAX_INOTIFY_EVENT 4096  ///< maximum inotify event size

/* fallback config */
#define FALLBACK_PACKET_THRESHOLD 5  ///< fallback packet threshold
#define FALLBACK_PORT_THRESHOLD 100  ///< fallback port threshold
#define FALLBACK_ALERT_THRESHOLD 3  ///< fallback alert threshold

/**
 * @brief Subnet representation
 */
struct subnet {
	in_addr_t network_addr;  ///< subnet address
	in_addr_t mask;  ///< subnet mask
};

/**
 * @brief IP list from config file
 */
struct config_ip_list {
	int size;
	in_addr_t *entries;
};

/**
 * @brief Subnet list from config file
 */
struct config_subnet_list {
	int size;
	struct subnet *entries;
};

/**
 * @brief port list from config file
 */
struct config_port_list {
	int size;
	int *entries;
};

/**
 * @brief Configuration
 */
struct config {
	int packet_threshold;  ///< number of packets to trigger a flag-based alert
	int port_threshold;  ///< number of ports to trigger a port-based alert
	int alert_threshold;  ///< number of alerts before blacklisting
	in_addr_t redirect_ip;  ///< IP address to redirect blacklisted traffic to
	bool block_src;  ///< true = block, false = redirect
	bool dry_run;  ///< true to enable dry run mode

	bool test;  ///< true to enable testing mode
	struct subnet test_subnet;  ///< testing subnet (log extra info)

	struct config_ip_list *blacklist_ip;  ///< blacklisted IPs
	struct config_ip_list *whitelist_ip;  ///< whitelisted IPs

	struct config_subnet_list *blacklist_subnet;  ///< blacklisted subnets
	struct config_subnet_list *whitelist_subnet;  ///< whitelisted subnets

	struct config_port_list *whitelist_port;  ///< whitelisted ports
};

/**
 * @brief Inotify worker thread arguments
 */
struct inotify_thread_args {
	char *config_path;  ///< path to config file
	char *config_dir;  ///< directory containing config file
	char *config_filename;  ///< name of config file
	struct config *current_config;  ///< current loaded config
	pthread_rwlock_t *lock;  ///< config lock
};

void str_tolower(char *str);
void cidr_to_subnet(char *cidr, struct subnet *subnet);

cJSON *json_config(const char *filename, FILE *log);
char *str_json_value(cJSON *obj, const char *item_name);
in_addr_t ip_json_value(cJSON *obj, const char *item_name);

struct config_ip_list *ip_list_json(cJSON *obj, const char *item_name, FILE *LOG);
struct config_subnet_list *subnet_list_json(cJSON *obj, const char *item_name, FILE *LOG);
struct config_port_list *port_list_json(cJSON *obj, const char *item_name, FILE *LOG);

int check_action(cJSON *json_obj, const char *item_name);
int int_json_value(cJSON *json_obj, const char *item_name,
		   const int MAX_THRESHOLD);
int bool_json_value(cJSON *json_obj, const char *item_name);

void drop_ips(struct config_ip_list *list);
void drop_subnets(struct config_subnet_list *list);
void drop_ports(struct config_port_list *list);

typedef void (*drop_func)(void *);
void drop_list(void *list, drop_func func);

void drop_config(struct config *config);


void fallback_config(struct config *config, pthread_rwlock_t *lock);
void apply_config(cJSON *config_json, struct config *current_config,
				  pthread_rwlock_t *lock, FILE *LOG);

#endif
