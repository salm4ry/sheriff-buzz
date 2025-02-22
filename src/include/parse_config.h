#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <ctype.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#include <pthread.h>
#include <unistd.h>
#include <poll.h>
#include <sys/inotify.h>

#include "log.h"
#include "pr.h"

FILE *LOG;

#define MAX_PACKET_THRESHOLD 1000
#define MAX_PORT_THRESHOLD 65536
#define MAX_FLAG_THRESHOLD 10

#define MAX_EVENT 4096

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
	char *config_dir;
	char *config_filename;
	struct config *current_config;
	pthread_rwlock_t *lock;
};

/**
 * Convert a string to lowercase
 */
char *str_lower(char *str)
{
	for (int i = 0; str[i]; i++) {
		str[i] = tolower(str[i]);
	}

	return str;
}

/* get network address and subnet mask given CIDR (slash notation) string */
void cidr_to_subnet(char *cidr, struct subnet *subnet)
{
	int bits;

	subnet->network_addr = 0;
	subnet->mask = 0;

	/* bits = number of bits in network number */
	bits = inet_net_pton(AF_INET, cidr,
			&subnet->network_addr, sizeof(subnet->network_addr));

	/* convert bits to subnet mask (based on ipcalc implementation) */
	subnet->mask = htonl(~((1 << (32 - bits)) - 1));
	/* convert resulting address to network address with bitwise AND */
	subnet->network_addr &= subnet->mask;
}

/**
 * Extract and parse config from JSON file
 *
 * return parsed JSON object on success, NULL on error
 */
cJSON *json_config(const char *filename)
{
	FILE *cfg;
	long cfg_size;
	cJSON *cfg_json = NULL;

	cfg = fopen(filename, "r");

	if (cfg) {
		/* get file size before reading */
		fseek(cfg, 0L, SEEK_END);
		/* +1 for EOF */
		cfg_size = ftell(cfg) + 1;
		/* rewind file pointer back to start */
		rewind(cfg);

		/* read file contents */
		char *tmp = (char *) calloc(cfg_size, sizeof(char));
		fread(tmp, sizeof(char), cfg_size, cfg);

		fclose(cfg);

		cfg_json = cJSON_Parse(tmp);
		free(tmp);

		if (!cfg_json) {
			log_error(LOG,  "cjson: %s\n", cJSON_GetErrorPtr());
			cJSON_Delete(cfg_json);
			return NULL;
		}
	}

	return cfg_json;
}

char *str_json_value(cJSON *obj, const char *item_name)
{
	char *value = NULL;
	cJSON *item;

	item = cJSON_GetObjectItemCaseSensitive(obj, item_name);
	if (cJSON_IsString(item) && (item->valuestring)) {
		/* +1 for null terminator */
		value = (char *) malloc((strlen(item->valuestring)+1) * sizeof(char));
		if (!value) {
			pr_err("memory allocation failed: %s\n", strerror(errno));
			exit(1);
		}

		strncpy(value, item->valuestring, strlen(item->valuestring)+1);
	}

	return value;
}

/**
 * Extract IP address from JSON item
 *
 * return parsed IP on success, -1 on error
 */
in_addr_t ip_json_value(cJSON *obj, const char *item_name)
{
	in_addr_t ip = 0;
	int res;

	char *value = str_json_value(obj, item_name);

	if (value) {
		/* inet_pton() returns 1 on success, 0 on error */
		res = inet_pton(AF_INET, value, &ip);
		if (res == 0) {
			return -1;
		}
	}

	free(value);

	return ip;
}

/**
 * Extract array of IP addresses from JSON item into long *
 *
 * return number of entries
 */
struct ip_list *ip_list_json(cJSON *obj, const char *item_name)
{
	/* TODO max blacklist/whitelist size- truncate accordingly */
	int index = 0;
	cJSON *array, *elem;
	struct ip_list *list;

	list = malloc(sizeof(struct ip_list));
	if (!list) {
		perror("memory allocation failed");
		exit(errno);
	}

	array = cJSON_GetObjectItemCaseSensitive(obj, item_name);
	list->size = cJSON_GetArraySize(array);
	if (list->size != 0) {
		list->entries = calloc(list->size, sizeof(in_addr_t));
		if (!list->entries) {
			perror("memory allocation failed");
			exit(errno);
		}

		/* extract IP addresses from array */
		cJSON_ArrayForEach(elem, array)
		{
			if (cJSON_IsString(elem) && elem->valuestring) {
				inet_pton(AF_INET, elem->valuestring, &list->entries[index]);
			}

			index++;
		}
	} else {
		free(list);
		list = NULL;
	}

	return list;
}

struct subnet_list *subnet_list_json(cJSON *obj, const char *item_name)
{
	int index = 0;
	cJSON *array, *elem;
	struct subnet_list *list;

	list = malloc(sizeof(struct subnet_list));
	if (!list) {
		perror("memory allocation failed");
		exit(errno);
	}

	array = cJSON_GetObjectItemCaseSensitive(obj, item_name);
	list->size = cJSON_GetArraySize(array);
	if (list->size != 0) {
		list->entries = calloc(list->size, sizeof(struct subnet));
		if (!list->entries) {
			perror("memory allocation failed");
			exit(errno);
		}

		/* extract subnets from array */
		cJSON_ArrayForEach(elem, array)
		{
			if (cJSON_IsString(elem) && elem->valuestring) {
				cidr_to_subnet(elem->valuestring, &list->entries[index]);
			}

			index++;
		}
	} else {
		free(list);
		list = NULL;
	}

	return list;
}

struct port_list *port_list_json(cJSON *obj, const char *item_name)
{
	int index = 0;
	cJSON *array, *elem;
	struct port_list *list;

	list = malloc(sizeof(struct port_list));
	if (!list) {
		perror("memory allocation failed");
		exit(errno);
	}

	array = cJSON_GetObjectItemCaseSensitive(obj, item_name);
	list->size = cJSON_GetArraySize(array);
	if (list->size != 0) {
		list->entries = calloc(list->size, sizeof(int));
		if (!list->entries) {
			perror("memory allocation failed");
			exit(errno);
		}

		/* extrat ports from array */
		cJSON_ArrayForEach(elem, array)
		{
			if (cJSON_IsNumber(elem) && elem->valueint) {
				list->entries[index] = elem->valueint;
			}
			index++;
		}
	} else {
		free(list);
		list = NULL;
	}

	return list;
}


/**
 * Extract block/redirect action from JSON item
 *
 * return 0/1 (false/true) on success, -1 on error
 */
int check_action(cJSON *json_obj, const char *item_name)
{
	int action = -1;
	char *value = str_json_value(json_obj, item_name);

	if (value) {
		value = str_lower(value);
		if (strncmp(value, "block", strlen(value)+1) == 0) {
			/* block */
			free(value);
			return 1;
		} else if (strncmp(value, "redirect", strlen(value)+1) == 0) {
			/* redirect */
			free(value);
			return 0;
		}
	}

	free(value);
	return action;
}

/**
 * Extract value of integer JSON item
 *
 * Threshold value must be > 0 and <= MAX_THRESHOLD
 * return integer value on success, -1 on error
 */
int threshold_json_value(
		cJSON *json_obj, const char *item_name, const int MAX_THRESHOLD)
{
	int value = 0;
	cJSON *item;

	item = cJSON_GetObjectItemCaseSensitive(json_obj, item_name);
	if (cJSON_IsNumber(item) && (item->valueint)) {
		value = item->valueint;
	}

	if (value <= 0 || value > MAX_THRESHOLD) {
		return -1;
	}

	return value;
}

/**
 * Extract value of boolean JSON item
 *
 * return 0/1 (false/true) on success, -1 on error
 */
int bool_json_value(cJSON *json_obj, const char *item_name)
{
	int value = -1;
	cJSON *item;

	item = cJSON_GetObjectItemCaseSensitive(json_obj, item_name);
	if (cJSON_IsBool(item)) {
		value = cJSON_IsTrue(item);
	}

	return value;
}


void free_ip_list(struct ip_list *list)
{
	if (list) {
		if (list->entries) {
			free(list->entries);
		}
		free(list);
	}
}

void free_subnet_list(struct subnet_list *list)
{
	if (list) {
		if (list->entries) {
			free(list->entries);
		}
		free(list);
	}
}

void free_port_list(struct port_list *list)
{
	if (list) {
		if (list->entries) {
			free(list->entries);
		}
		free(list);
	}
}

void free_config(struct config *config)
{
	free_ip_list(config->blacklist_ip);
	free_ip_list(config->whitelist_ip);
	free_subnet_list(config->blacklist_subnet);
	free_subnet_list(config->whitelist_subnet);
	free_port_list(config->whitelist_port);
}

/* config to use when default config file unavailable/invalid */
void fallback_config(struct config *config, pthread_rwlock_t *lock)
{
	pthread_rwlock_wrlock(lock);
	config->packet_threshold = 5;
	config->port_threshold = 100;
	config->alert_threshold = 3;

	/* block by default (no IP to redirect to) */
	config->block_src = true;
	config->redirect_ip = -1;

	/* blacklist + whitelists empty initially */
	config->blacklist_ip = NULL;
	config->whitelist_ip = NULL;
	config->blacklist_subnet = NULL;
	config->whitelist_subnet = NULL;
	config->whitelist_port = NULL;

	config->dry_run = false;
	pthread_rwlock_unlock(lock);
}

void apply_config(cJSON *config_json, struct config *current_config,
		pthread_rwlock_t *lock)
{
	int packet_threshold, port_threshold, alert_threshold, block_src;
	in_addr_t redirect_ip;

	struct ip_list *blacklist_ip, *whitelist_ip;
	struct subnet_list *blacklist_subnet, *whitelist_subnet;
	struct port_list *whitelist_port;

	/* read thresholds */
	packet_threshold = threshold_json_value(config_json,
			"packet_threshold", MAX_PACKET_THRESHOLD);
	port_threshold = threshold_json_value(config_json,
			"port_threshold", MAX_PORT_THRESHOLD);
	alert_threshold = threshold_json_value(config_json,
			"alert_threshold", MAX_FLAG_THRESHOLD);

	/* block or redirect flagged IP? */
	block_src = check_action(config_json, "action");
	redirect_ip = ip_json_value(config_json, "redirect_ip");

	if (!block_src && redirect_ip != -1) {
		/* redirect: check IP address and only apply if a valid IP is supplied */
		pthread_rwlock_wrlock(lock);
		current_config->block_src = false;
		current_config->redirect_ip = redirect_ip;
		pthread_rwlock_unlock(lock);

		char ip_str[16];
		inet_ntop(AF_INET, &redirect_ip, ip_str, 16);
		log_info(LOG, "config: action = redirect to %s\n", ip_str);
	} else {
		pthread_rwlock_wrlock(lock);
		current_config->block_src = true;
		pthread_rwlock_unlock(lock);
		log_info(LOG, "config: %s\n", "action = block");
	}

	/* apply thresholds if valid */
	if (packet_threshold != -1) {
		pthread_rwlock_wrlock(lock);
		current_config->packet_threshold = packet_threshold;
		pthread_rwlock_unlock(lock);
		log_info(LOG, "config: packet_threshold = %d\n", packet_threshold);
	}
	if (port_threshold != -1) {
		pthread_rwlock_wrlock(lock);
		current_config->port_threshold = port_threshold;
		pthread_rwlock_unlock(lock);
		log_info(LOG, "config: port_threshold = %d\n", port_threshold);
	}
	if (alert_threshold != -1) {
		pthread_rwlock_wrlock(lock);
		current_config->alert_threshold = alert_threshold;
		pthread_rwlock_unlock(lock);
		log_info(LOG, "config: alert_threshold = %d\n", alert_threshold);
	}

	/* IP blacklist and whitelist */
	blacklist_ip = ip_list_json(config_json, "blacklist_ip");
	whitelist_ip = ip_list_json(config_json, "whitelist_ip");

	/* subnet blacklist and whitelist */
	blacklist_subnet = subnet_list_json(config_json, "blacklist_subnet");
	whitelist_subnet = subnet_list_json(config_json, "whitelist_subnet");

	/* port whitelist */
	whitelist_port = port_list_json(config_json, "whitelist_port");

	pthread_rwlock_wrlock(lock);
	free_config(current_config);

	current_config->blacklist_ip = blacklist_ip;
	current_config->whitelist_ip = whitelist_ip;
	current_config->blacklist_subnet = blacklist_subnet;
	current_config->whitelist_subnet = whitelist_subnet;
	current_config->whitelist_port = whitelist_port;
	pthread_rwlock_unlock(lock);
}
