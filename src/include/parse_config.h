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

#define MAX_LIST 256
#define MAX_PACKET_THRESHOLD 1000
#define MAX_PORT_THRESHOLD 65536
#define MAX_FLAG_THRESHOLD 10

#define MIN_PORT 0
#define MAX_PORT 65535

#define REDIRECT 0
#define BLOCK 1
#define UNDEFINED -1

#define MAX_EVENT 4096

/* fallback config */
#define FALLBACK_PACKET_THRESHOLD 5
#define FALLBACK_PORT_THRESHOLD 100
#define FALLBACK_ALERT_THRESHOLD 3

struct subnet {
	in_addr_t network_addr;
	in_addr_t mask;
};

struct ip_list {
	int size;
	in_addr_t *entries;
};

struct subnet_list {
	int size;
	struct subnet *entries;
};

struct port_list {
	int size;
	int *entries;
};

struct config {
	int packet_threshold;
	int alert_threshold;
	int port_threshold;
	in_addr_t redirect_ip;
	bool block_src;
	bool dry_run;

	struct ip_list *blacklist_ip;
	struct ip_list *whitelist_ip;

	struct subnet_list *blacklist_subnet;
	struct subnet_list *whitelist_subnet;

	struct port_list *whitelist_port;
};

struct inotify_thread_args {
	char *config_path;
	char *config_dir;
	char *config_filename;
	struct config *current_config;
	pthread_rwlock_t *lock;
};

void str_tolower(char *str);
void cidr_to_subnet(char *cidr, struct subnet *subnet);

cJSON *json_config(const char *filename, FILE *log);
char *str_json_value(cJSON *obj, const char *item_name);
in_addr_t ip_json_value(cJSON *obj, const char *item_name);

struct ip_list *ip_list_json(cJSON *obj, const char *item_name, FILE *LOG);
struct subnet_list *subnet_list_json(cJSON *obj, const char *item_name, FILE *LOG);
struct port_list *port_list_json(cJSON *obj, const char *item_name, FILE *LOG);

int check_action(cJSON *json_obj, const char *item_name);
int int_json_value(cJSON *json_obj, const char *item_name,
		   const int MAX_THRESHOLD);
int bool_json_value(cJSON *json_obj, const char *item_name);

void drop_ips(struct ip_list *list);
void drop_subnets(struct subnet_list *list);
void drop_ports(struct port_list *list);

typedef void (*drop_func)(void *);
void drop_list(void *list, drop_func func);

void drop_config(struct config *config);


void fallback_config(struct config *config, pthread_rwlock_t *lock);
void apply_config(cJSON *config_json, struct config *current_config,
				  pthread_rwlock_t *lock, FILE *LOG);

#endif
