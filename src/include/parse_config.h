#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

#define CONFIG_PATH_LEN 20 /* number of bytes for config file path */

#define MAX_PACKET_THRESHOLD 1000
#define MAX_PORT_THRESHOLD 65536
#define MAX_FLAG_THRESHOLD 10

#define MAX_EVENT 4096

struct ip_list {
	int size;
	unsigned long *entries;
};

struct config {
	int packet_threshold;
	int flag_threshold;
	unsigned long port_threshold;
	unsigned long redirect_ip;
	bool block_src;

	struct ip_list *ip_blacklist;
	struct ip_list *ip_whitelist;
};

struct inotify_thread_args {
	struct config *current_config;
	pthread_rwlock_t *lock;
};

char config_path[CONFIG_PATH_LEN];

/**
 * Convert a string to lowercase
 */
static char *str_lower(char *str)
{
	for (int i = 0; str[i]; i++) {
		str[i] = tolower(str[i]);
	}

	return str;
}

/**
 * Extract and parse config from JSON file
 *
 * return parsed JSON object on success, NULL on error
 */
static cJSON *json_config(const char *filename)
{
	FILE *config_file;
	long file_size;
	cJSON *obj = NULL;
	char *file_contents;
	const char *error;

	config_file = fopen(filename, "r");
	if (config_file) {
		/* get file size before reading */
		fseek(config_file, 0L, SEEK_END);
		/* +1 for EOF */
		file_size = ftell(config_file) + 1;
		/* rewind file pointer back to start */
		rewind(config_file);

		/* read file contents */
		file_contents = (char *) calloc(file_size, sizeof(char));
		fread(file_contents, sizeof(char), file_size, config_file);

		fclose(config_file);

		obj = cJSON_Parse(file_contents);
		free(file_contents);
		if (!obj) {
			error = cJSON_GetErrorPtr();
			if (error) {
				fprintf(stderr, "cjson: %s\n", error);
			}
			cJSON_Delete(obj);
			return NULL;
		}
	}

	return obj;
}

static char *str_json_value(cJSON *obj, const char *item_name)
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
static long ip_json_value(cJSON *obj, const char *item_name)
{
	long ip = -1;
	int res;

	char *value = str_json_value(obj, item_name);

	if (value) {
		/* inet_pton() returns 1 on success, 0 on error */
		res = inet_pton(AF_INET, value, &ip);
		if (res == 0) {
			ip = -1;
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
		pr_err("memory allocation failed: %s\n", strerror(errno));
		exit(1);
	}

	array = cJSON_GetObjectItemCaseSensitive(obj, item_name);
	list->size = cJSON_GetArraySize(array);
	if (list->size != 0) {
		list->entries = calloc(list->size, sizeof(unsigned long));
		if (!list->entries) {
			pr_err("memory allocation failed: %s\n", strerror(errno));
			exit(1);
		}

#ifdef DEBUG
		log_debug("%s size = %d\n", item_name, list->size);
#endif

		/* extract IP addresses from array */
		cJSON_ArrayForEach(elem, array)
		{
			if (cJSON_IsString(elem) && elem->valuestring) {
				inet_pton(AF_INET, elem->valuestring, &list->entries[index]);
			}

			index++;
		}
	}

	return list;
}


/**
 * Extract block/redirect action from JSON item
 *
 * return 0/1 (false/true) on success, -1 on error
 */
static int check_action(cJSON *json_obj, const char *item_name)
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
static long threshold_json_value(
		cJSON *json_obj, const char *item_name, const int MAX_THRESHOLD)
{
	long value = 0;
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

static void set_default_config(struct config *config, pthread_rwlock_t *lock)
{
	pthread_rwlock_wrlock(lock);
	config->packet_threshold = 5;
	config->port_threshold = 100;
	config->flag_threshold = 3;

	/* block by default */
	config->block_src = true;
	config->redirect_ip = -1;

	/* blacklist + whitelists empty initially */
	config->ip_blacklist = NULL;
	config->ip_whitelist = NULL;

	pthread_rwlock_unlock(lock);
}

static void apply_config(cJSON *config_json, struct config *current_config,
		pthread_rwlock_t *lock)
{
	int packet_threshold, flag_threshold, block_src;
	unsigned long redirect_ip;
	long port_threshold;

	struct ip_list *ip_blacklist, *ip_whitelist;

	/* read thresholds */
	packet_threshold = threshold_json_value(config_json,
			"packet_threshold", MAX_PACKET_THRESHOLD);
	port_threshold = threshold_json_value(config_json,
			"port_threshold", MAX_PORT_THRESHOLD);
	flag_threshold = threshold_json_value(config_json,
			"flag_threshold", MAX_FLAG_THRESHOLD);

	/* block or redirect flagged IP? */
	block_src = check_action(config_json, "action");
	redirect_ip = ip_json_value(config_json, "redirect_ip");

	if (!block_src && redirect_ip != -1) {
		/* redirect: check IP address and only apply if a valid IP is supplied */
		pthread_rwlock_wrlock(lock);
		current_config->block_src = false;
		current_config->redirect_ip = redirect_ip;
		pthread_rwlock_unlock(lock);
#ifdef DEBUG
		char ip_str[16];
		inet_ntop(AF_INET, &redirect_ip, ip_str, 16);
		log_debug("config: action = redirect to %s\n", ip_str);
#endif
	} else {
		pthread_rwlock_wrlock(lock);
		current_config->block_src = true;
		pthread_rwlock_unlock(lock);
#ifdef DEBUG
		log_debug("config: %s\n", "action = block");
#endif
	}

	/* apply thresholds if valid */
	if (packet_threshold != -1) {
		pthread_rwlock_wrlock(lock);
		current_config->packet_threshold = packet_threshold;
		pthread_rwlock_unlock(lock);
#ifdef DEBUG
		log_debug("config: packet_threshold = %d\n", packet_threshold);
#endif
	}
	if (port_threshold != -1) {
		pthread_rwlock_wrlock(lock);
		current_config->port_threshold = port_threshold;
		pthread_rwlock_unlock(lock);
#ifdef DEBUG
		log_debug("config: port_threshold = %d\n", port_threshold);
#endif
	}
	if (flag_threshold != -1) {
		pthread_rwlock_wrlock(lock);
		current_config->flag_threshold = flag_threshold;
		pthread_rwlock_unlock(lock);
#ifdef DEBUG
		log_debug("config: flag_threshold = %d\n", flag_threshold);
#endif
	}

	/* blacklist and whitelist */
	ip_blacklist = ip_list_json(config_json, "ip_blacklist");
	ip_whitelist = ip_list_json(config_json, "ip_whitelist");

	pthread_rwlock_wrlock(lock);
	if (current_config->ip_blacklist) {
		if (current_config->ip_blacklist->entries) {
			free(current_config->ip_blacklist->entries);
		}
		free(current_config->ip_blacklist);
	}

	if (current_config->ip_whitelist) {
		if (current_config->ip_whitelist->entries) {
			free(current_config->ip_whitelist->entries);
		}
		free(current_config->ip_whitelist);
	}

	current_config->ip_blacklist = ip_blacklist;
	current_config->ip_whitelist = ip_whitelist;

	pthread_rwlock_unlock(lock);
}
