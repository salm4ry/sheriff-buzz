#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include <netinet/in.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#include <pthread.h>
#include <unistd.h>
#include <poll.h>
#include <sys/inotify.h>

#include "include/parse_config.h"
#include "include/log.h"

/*
 * Convert a string to lowercase
 */
void str_tolower(char *str)
{
	if (!str)
		return;

	while (*str != '\0') {
		*str = tolower((unsigned char)*str);
		str++;
	}
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

/*
 * Extract and parse config from JSON file
 * return parsed JSON object on success, NULL on error
 */
cJSON *json_config(const char *filename, FILE *LOG)
{
	FILE *cfg;
	long cfg_size;
	char *buf = NULL;
	cJSON *cfg_json = NULL;

	int err = 0;

	cfg = fopen(filename, "r");
	if (!cfg) {
		log_error(LOG, "%s:%s:%d %s\n", __FILE__, __func__, __LINE__, strerror(errno));
		goto out;
	}

	/* get file size before reading */
	if (fseek(cfg, 0L, SEEK_END) == -1) {
		log_error(LOG, "%s:%s:%d %s\n", __FILE__, __func__, __LINE__, strerror(errno));
		goto cleanup;
	}
	/* +1 for EOF */
	cfg_size = ftell(cfg) + 1;

	if (cfg_size == 0) {
		log_error(LOG, "%s:%s:%d %s\n", __FILE__, __func__, __LINE__, strerror(errno));
		goto cleanup;
	}

	buf = (char *) calloc(cfg_size, sizeof(char));
	if (!buf) {
		log_error(LOG, "%s:%s:%d %s\n", __FILE__, __func__, __LINE__, strerror(errno));
		goto cleanup;
	}

	/* rewind file pointer back to start */
	clearerr(cfg);
	rewind(cfg);
	err = errno;

	if (ferror(cfg)) {
		log_error(LOG, "%s:%s:%d error rewinding file: %s\n", __FILE__, __func__, __LINE__, strerror(err));
		goto cleanup;
	}

	/* read file contents */
	fread(buf, sizeof(char), cfg_size, cfg);
	/* use feof() and ferror() to distinguish between end of file and error */
	if (!feof(cfg) && ferror(cfg)) {
		log_error(LOG, "%s:%s:%d error reading file\n", __FILE__, __func__, __LINE__);
	}

	cfg_json = cJSON_Parse(buf);

	if (!cfg_json) {
		log_error(LOG, "cjson: %s\n", cJSON_GetErrorPtr());
		cJSON_Delete(cfg_json);
	}

cleanup:
	fclose(cfg);
out:
	free(buf);
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
			exit(errno);
		}

		strncpy(value, item->valuestring, strlen(item->valuestring)+1);
	}

	return value;
}

/*
 * Extract IP address from JSON item
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
			return UNDEFINED;
		}
	}

	free(value);

	return ip;
}

struct subnet subnet_json_value(cJSON *obj, const char *item_name)
{
	struct subnet subnet = {0, 0};

	char *value = str_json_value(obj, item_name);

	if (value) {
		cidr_to_subnet(value, &subnet);
	}

	free(value);

	return subnet;
}

/*
 * Extract array of IP addresses from JSON item into long
 * return number of entries
 */
struct ip_list *ip_list_json(cJSON *obj, const char *item_name, FILE *LOG)
{
	int index = 0;
	cJSON *array, *elem;
	struct ip_list *list;

	list = malloc(sizeof(struct ip_list));
	if (!list) {
		p_error("failed to allocate IP address list");
		exit(errno);
	}

	array = cJSON_GetObjectItemCaseSensitive(obj, item_name);
	list->size = cJSON_GetArraySize(array);
	if (list->size != 0) {
		if (list->size > MAX_IP_LIST) {
			log_info(LOG, "config: %s list exceeds maximum size %d, truncating\n",
				 item_name, MAX_IP_LIST);
			list->size = MAX_IP_LIST;
		}

		list->entries = calloc(list->size, sizeof(in_addr_t));
		if (!list->entries) {
			p_error("failed to allocate IP address list entries");
			exit(errno);
		}

		/* extract IP addresses from array */
		cJSON_ArrayForEach(elem, array) {
			if (index >= MAX_IP_LIST) {
				/* stop reading in elements after maximum list size */
				break;
			}

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

struct subnet_list *subnet_list_json(cJSON *obj, const char *item_name, FILE *LOG)
{
	int index = 0;
	cJSON *array, *elem;
	struct subnet_list *list;

	list = malloc(sizeof(struct subnet_list));
	if (!list) {
		p_error("failed to allocate subnet list");
		exit(errno);
	}

	array = cJSON_GetObjectItemCaseSensitive(obj, item_name);
	list->size = cJSON_GetArraySize(array);
	if (list->size != 0) {
		if (list->size > MAX_SUBNET_LIST) {
			log_info(LOG, "config: %s list exceeds maximum size %d, truncating\n",
				 item_name, MAX_SUBNET_LIST);
			list->size = MAX_SUBNET_LIST;
		}

		list->entries = calloc(list->size, sizeof(struct subnet));
		if (!list->entries) {
			p_error("failed to allocate subnet list entries");
			exit(errno);
		}

		/* extract subnets from array */
		cJSON_ArrayForEach(elem, array) {
			if (index >= MAX_SUBNET_LIST) {
				/* stop reading in elements after maximum list size */
				break;
			}

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

struct port_list *port_list_json(cJSON *obj, const char *item_name, FILE *LOG)
{
	int index = 0;
	cJSON *array, *elem;
	struct port_list *list;

	list = malloc(sizeof(struct port_list));
	if (!list) {
		p_error("failed to allocate port list");
		exit(errno);
	}

	array = cJSON_GetObjectItemCaseSensitive(obj, item_name);
	list->size = cJSON_GetArraySize(array);
	if (list->size != 0) {
		if (list->size > MAX_PORT_LIST) {
			log_info(LOG, "config: %s list exceeds maximum size %d, truncating\n",
				 item_name, MAX_PORT_LIST);
			list->size = MAX_PORT_LIST;
		}

		list->entries = calloc(list->size, sizeof(int));
		if (!list->entries) {
			p_error("failed to allocate port list entries");
			exit(errno);
		}

		log_debug(LOG, "config: total port entries: %d\n", list->size);

		/* extract ports from array */
		cJSON_ArrayForEach(elem, array) {
			if (index >= MAX_PORT_LIST) {
				/* stop reading in elements after maximum list size */
				break;
			}

			if (cJSON_IsNumber(elem) && elem->valueint) {
				/* port bounds checking */
				if (elem->valueint < MIN_PORT || elem->valueint > MAX_PORT) {
					log_error(LOG, "config: invalid port %d\n", elem->valueint);
					list->size--;
				} else {
					/* only update list and index if port is valid */
					list->entries[index] = elem->valueint;
					index++;
				}
			}
		}

		/* remove invalid ports from count */
		log_debug(LOG, "config: total valid port entries: %d\n", list->size);
	} else {
		free(list);
		list = NULL;
	}

	return list;
}


/*
 * Extract block/redirect action from JSON item
 *
 * return 0/1 (false/true) on success, -1 on error
 */
int check_action(cJSON *json_obj, const char *item_name)
{
	int action = UNDEFINED;
	char *value = str_json_value(json_obj, item_name);

	if (!value)
		goto out;

	str_tolower(value);

	if (strncmp(value, "block", strlen(value)+1) == 0) {
		action = BLOCK;
	} else if (strncmp(value, "redirect", strlen(value)+1) == 0) {
		action = REDIRECT;
	}

out:
	free(value);
	return action;
}

/*
 * Extract value of integer/boolean JSON item
 *
 * - json_obj: JSON object to extract value from
 * - item_name: name of item to extract value of
 * - MAX_THRESHOLD: maximum threshold to compare for threshold values; ignore if
 *   set to UNDEFINED (e.g. for booleans)
 */
int int_json_value(cJSON *json_obj, const char *item_name,
		   const int MAX_THRESHOLD)
{
	int value = UNDEFINED;
	cJSON *item;

	item = cJSON_GetObjectItemCaseSensitive(json_obj, item_name);

	if (!item)
		goto out;

	switch (MAX_THRESHOLD) {
	case UNDEFINED:
		/* extract boolean */
		if (cJSON_IsBool(item))
			value = cJSON_IsTrue(item);
		break;
	default:
		/* extract thresholded integer */
		if (cJSON_IsNumber(item) && (item->valueint > 0 && item->valueint <= MAX_THRESHOLD))
			value = item->valueint;
		break;
	}

out:
	return value;
}


void drop_ips(struct ip_list *list)
{
	if (list) {
		if (list->entries) {
			free(list->entries);
		}
		free(list);
	}
}

void drop_subnets(struct subnet_list *list)
{
	if (list) {
		if (list->entries) {
			free(list->entries);
		}
		free(list);
	}
}

void drop_ports(struct port_list *list)
{
	if (list) {
		if (list->entries) {
			free(list->entries);
		}
		free(list);
	}
}

void drop_list(void *list, drop_func func)
{
	func(list);
}


void drop_config(struct config *config)
{
	drop_list(config->blacklist_ip, (drop_func)drop_ips);
	drop_list(config->whitelist_ip, (drop_func)drop_ips);
	drop_list(config->blacklist_subnet, (drop_func)drop_subnets);
	drop_list(config->whitelist_subnet, (drop_func)drop_subnets);
	drop_list(config->whitelist_port, (drop_func)drop_ports);
}

/* config to use when default config file unavailable/invalid */
/* define the numerical constants in the header file */
void fallback_config(struct config *config, pthread_rwlock_t *lock)
{
	pthread_rwlock_wrlock(lock);
	config->packet_threshold = FALLBACK_PACKET_THRESHOLD;
	config->port_threshold = FALLBACK_PORT_THRESHOLD;
	config->alert_threshold = FALLBACK_ALERT_THRESHOLD;

	/* block by default (no IP to redirect to) */
	config->block_src = true;
	config->redirect_ip = UNDEFINED;

	/* blacklist + whitelists empty initially */
	config->blacklist_ip = NULL;
	config->whitelist_ip = NULL;
	config->blacklist_subnet = NULL;
	config->whitelist_subnet = NULL;
	config->whitelist_port = NULL;

	config->dry_run = false;

	config->test = false;
	cidr_to_subnet("10.10.0.0/16", &config->test_subnet);
	pthread_rwlock_unlock(lock);
}

void apply_config(cJSON *config_json, struct config *current_config,
		pthread_rwlock_t *lock, FILE *LOG)
{
	int packet_threshold, port_threshold, alert_threshold, block_src;
	int dry_run, test; /* booleans */

	in_addr_t redirect_ip;

	struct ip_list *blacklist_ip, *whitelist_ip;
	struct subnet_list *blacklist_subnet, *whitelist_subnet;
	struct port_list *whitelist_port;
	struct subnet test_subnet;

	/* read thresholds */
	packet_threshold = int_json_value(config_json,
						"packet_threshold", MAX_PACKET_THRESHOLD);
	port_threshold = int_json_value(config_json,
					      "port_threshold", MAX_PORT_THRESHOLD);
	alert_threshold = int_json_value(config_json,
					       "alert_threshold", MAX_FLAG_THRESHOLD);

	dry_run = int_json_value(config_json, "dry_run", UNDEFINED);

	test = int_json_value(config_json, "test", UNDEFINED);
	test_subnet = subnet_json_value(config_json, "test_subnet");

	/* block or redirect flagged IP? */
	block_src = check_action(config_json, "action");
	redirect_ip = ip_json_value(config_json, "redirect_ip");

	if (!block_src && redirect_ip != UNDEFINED) {
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
	if (packet_threshold != UNDEFINED) {
		pthread_rwlock_wrlock(lock);
		current_config->packet_threshold = packet_threshold;
		pthread_rwlock_unlock(lock);
		log_info(LOG, "config: packet_threshold = %d\n", packet_threshold);
	}
	if (port_threshold != UNDEFINED) {
		pthread_rwlock_wrlock(lock);
		current_config->port_threshold = port_threshold;
		pthread_rwlock_unlock(lock);
		log_info(LOG, "config: port_threshold = %d\n", port_threshold);
	}
	if (alert_threshold != UNDEFINED) {
		pthread_rwlock_wrlock(lock);
		current_config->alert_threshold = alert_threshold;
		pthread_rwlock_unlock(lock);
		log_info(LOG, "config: alert_threshold = %d\n", alert_threshold);
	}

	/* apply booleans if valid */
	if (dry_run != UNDEFINED) {
		pthread_rwlock_wrlock(lock);
		current_config->dry_run = dry_run;
		pthread_rwlock_unlock(lock);
		log_info(LOG, "config: dry_run = %d\n", dry_run);
	}
	if (test != UNDEFINED) {
		pthread_rwlock_wrlock(lock);
		current_config->test = test;
		pthread_rwlock_unlock(lock);
		log_info(LOG, "config: test = %d\n", test);
	}
	if (test_subnet.mask != 0) {
		pthread_rwlock_wrlock(lock);
		current_config->test = test;
		pthread_rwlock_unlock(lock);
		log_info(LOG, "config: test subnet set\n", test);
	}

	/* IP blacklist and whitelist */
	blacklist_ip = ip_list_json(config_json, "blacklist_ip", LOG);
	whitelist_ip = ip_list_json(config_json, "whitelist_ip", LOG);

	if (blacklist_ip) {
		log_debug(LOG, "config: IP blacklist length = %d\n", blacklist_ip->size);
	}

	if (whitelist_ip) {
		log_debug(LOG, "config: IP whitelist length = %d\n", whitelist_ip->size);
	}

	/* subnet blacklist and whitelist */
	blacklist_subnet = subnet_list_json(config_json, "blacklist_subnet", LOG);
	whitelist_subnet = subnet_list_json(config_json, "whitelist_subnet", LOG);

	if (blacklist_subnet) {
		log_debug(LOG, "config: subnet blacklist length = %d\n", blacklist_subnet->size);
	}

	if (whitelist_subnet) {
		log_debug(LOG, "config: subnet whitelist length = %d\n", whitelist_subnet->size);
	}

	/* port whitelist */
	whitelist_port = port_list_json(config_json, "whitelist_port", LOG);
	if (whitelist_port) {
		log_debug(LOG, "config: port whitelist length = %d\n", whitelist_port->size);
	}

	pthread_rwlock_wrlock(lock);
	drop_config(current_config);

	current_config->blacklist_ip = blacklist_ip;
	current_config->whitelist_ip = whitelist_ip;
	current_config->blacklist_subnet = blacklist_subnet;
	current_config->whitelist_subnet = whitelist_subnet;
	current_config->whitelist_port = whitelist_port;
	pthread_rwlock_unlock(lock);
}
