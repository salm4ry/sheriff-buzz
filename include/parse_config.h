#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

#include "pr.h"

/**
 * Extract and parse config from JSON file
 *
 * return parsed JSON object on success, -1 on error
 */
cJSON *get_config(const char *filename)
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
		file_size = ftell(config_file);
		/* rewind file pointer back to start */
		rewind(config_file);

		fseek(config_file, 0L, SEEK_END);
		/* +1 for EOF */
		file_size = ftell(config_file) + 1;
		rewind(config_file);

		/* read file contents */
		file_contents = calloc(file_size, sizeof(char));
		fread(file_contents, sizeof(char), file_size, config_file);

		fclose(config_file);

		obj = cJSON_Parse(file_contents);
		if (!obj) {
			error = cJSON_GetErrorPtr();
			if (error) {
				pr_err("cjson: %s\n", error);
			}
			cJSON_Delete(obj);
			return NULL;
		}
		free(file_contents);
	}

	return obj;
}

/**
 * Extract value of string JSON item
 *
 * return string value on success, -1 on error
 */
char *str_json_value(cJSON *json_obj, char *item_name)
{
	char *value = NULL;
	cJSON *item;

	item = cJSON_GetObjectItemCaseSensitive(json_obj, item_name);
	if (cJSON_IsString(item) && (item->valuestring)) {
		/* +1 for null terminator */
		value = malloc((strlen(item->valuestring)+1) * sizeof(char));
		strncpy(value, item->valuestring, strlen(item->valuestring)+1);
	}

	return value;
}

/**
 * Extract value of integer JSON item
 *
 * return integer value on success, -1 on error
 */
int int_json_value(cJSON *json_obj, char *item_name)
{
	int value = -1;
	cJSON *item;

	item = cJSON_GetObjectItemCaseSensitive(json_obj, item_name);
	if (cJSON_IsString(item) && (item->valueint)) {
		value = item->valueint;
	}

	return value;
}
