#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <ctype.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

#include "log.h"

FILE *LOG;

#define MAX_PACKET_THRESHOLD 1000
#define MAX_PORT_THRESHOLD 65536
#define MAX_FLAG_THRESHOLD 10

struct config {
	int packet_threshold;
	int flag_threshold;
	long port_threshold;
	long redirect_ip;
	bool block_src;
};

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
static cJSON *get_config(const char *filename)
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

static char *str_json_value(cJSON *json_obj, const char *item_name)
{
	char *value = NULL;
	cJSON *item;

	item = cJSON_GetObjectItemCaseSensitive(json_obj, item_name);
	if (cJSON_IsString(item) && (item->valuestring)) {
		/* +1 for null terminator */
		value = (char *) malloc((strlen(item->valuestring)+1) * sizeof(char));
		strncpy(value, item->valuestring, strlen(item->valuestring)+1);
	}

	return value;
}

/**
 * Extract IP address from JSON item
 *
 * return parsed IP on success, -1 on error
 */
static long ip_json_value(cJSON *json_obj, const char *item_name)
{
	long ip = -1;
	int res;

	char *value = str_json_value(json_obj, item_name);

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
 * Extract block/redirect action from JSON item
 *
 * return 0/1 (false/true) on success, -1 on error
 */
static int check_action(cJSON *json_obj, const char *item_name,
		struct config *current_config)
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
	long value;
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
/*
static int bool_json_value(cJSON *json_obj, const char *item_name)
{
	int value = -1;
	cJSON *item;

	item = cJSON_GetObjectItemCaseSensitive(json_obj, item_name);
	if (cJSON_IsBool(item)) {
		value = item->valueint;
	}

	return value;
}
*/

static void set_default_config(struct config *config)
{
	config->packet_threshold = 5;
	config->port_threshold = 100;
	config->flag_threshold = 3;

	/* block by default */
	config->block_src = true;
	config->redirect_ip = -1;
}

static void apply_config(cJSON *config_json, struct config *current_config)
{
	int packet_threshold, flag_threshold, block_src;
	long port_threshold, redirect_ip;

	/* read thresholds */
	packet_threshold = threshold_json_value(config_json,
			"packet_threshold", MAX_PACKET_THRESHOLD);
	port_threshold = threshold_json_value(config_json,
			"port_threshold", MAX_PORT_THRESHOLD);
	flag_threshold = threshold_json_value(config_json,
			"flag_threshold", MAX_FLAG_THRESHOLD);

	/* block or redirect flagged IP? */
	block_src = check_action(config_json, "action", current_config);
	redirect_ip = ip_json_value(config_json, "redirect_ip");

	if (!block_src && redirect_ip != -1) {
		/* redirect: check IP address and only apply if a valid IP is supplied */
		current_config->block_src = false;
		current_config->redirect_ip = redirect_ip;
#ifdef DEBUG
		char ip_str[16];
		inet_ntop(AF_INET, &redirect_ip, ip_str, 16);
		log_debug("config: action = redirect to %s\n", ip_str);
#endif
	} else {
		current_config->block_src = true;
#ifdef DEBUG
		log_debug("config: %s", "action = block\n");
#endif
	}

	/* apply thresholds if valid */
	if (packet_threshold != -1) {
		current_config->packet_threshold = packet_threshold;
#ifdef DEBUG
		log_debug("config: packet_threshold = %d", packet_threshold);
#endif
	}
	if (port_threshold != -1) {
		current_config->port_threshold = port_threshold;
#ifdef DEBUG
		log_debug("config: port_threshold = %d", port_threshold);
#endif
	}
	if (flag_threshold != -1) {
		current_config->flag_threshold = flag_threshold;
#ifdef DEBUG
		log_debug("config: flag_threshold = %d", flag_threshold);
#endif
	}
}
