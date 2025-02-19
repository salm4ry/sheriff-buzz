#include <errno.h>
#include <time.h>

#define MAX_LOG_MSG 512
#include <stdio.h>

#define MAX_TIME_STR 20
#define MAX_PREFIX 28
#define TIME_FMT "%Y-%m-%d %H-%M-%S"

#ifndef _log_h
#define _log_h

/* TODO rewrite as functions that take variable arguments */

void make_prefix(char *prefix, char *base)
{
	char time_str[MAX_TIME_STR];
	time_t current_time = time(NULL);
	struct tm tm;
	localtime_r(&current_time, &tm);

	strftime(time_str, MAX_TIME_STR, TIME_FMT, &tm);
	snprintf(prefix, MAX_PREFIX, "%s %s", time_str, base);
}
#endif

#define make_msg(msg, fmt, ...) \
	snprintf(msg, MAX_LOG_MSG, fmt, ##__VA_ARGS__);

#define log(prefix, fmt, ...) \
{ \
	char *msg = malloc(MAX_LOG_MSG * sizeof(char)); \
	char *new_fmt = malloc(MAX_LOG_MSG * sizeof(char)); \
	\
	if (!msg || !new_fmt) { \
		fprintf(stderr, "memory allocation failed: %s", strerror(errno)); \
		exit(1); \
	} \
	\
	strncpy(new_fmt, prefix, MAX_LOG_MSG); \
	strncat(new_fmt, fmt, MAX_LOG_MSG - (strlen(new_fmt)+1)); \
	make_msg(msg, new_fmt, ##__VA_ARGS__); \
	fputs(msg, LOG); \
	fflush(LOG); \
	free(msg); \
	free(new_fmt); \
}

#ifdef DEBUG
	#define log_debug(fmt, ...) \
	{ \
		char prefix[MAX_PREFIX]; \
		make_prefix(prefix, "debug: "); \
		log(prefix, fmt, ##__VA_ARGS__); \
	}
#else
	#define log_debug(fmt, ...) \
		;
#endif

#define log_info(fmt, ...) \
{ \
	char prefix[MAX_PREFIX]; \
	make_prefix(prefix, "info: "); \
	log(prefix, fmt, ##__VA_ARGS__); \
}

#define log_error(fmt, ...) \
{ \
	char prefix[MAX_PREFIX]; \
	make_prefix(prefix, "error: "); \
	log(prefix, fmt, ##__VA_ARGS__); \
}

/* TODO rewrite to check for dry run */
#define log_alert(fmt, ...) \
{ \
	char prefix[MAX_PREFIX]; \
	make_prefix(prefix, "alert: "); \
	log(prefix, fmt, ##__VA_ARGS__); \
}
