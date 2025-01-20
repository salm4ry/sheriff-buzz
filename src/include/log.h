#include <errno.h>

#define MAX_LOG_MSG 512

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

#define log_debug(fmt, ...) \
{ \
	log("debug: ", fmt, ##__VA_ARGS__); \
}

#define log_error(fmt, ...) \
{ \
	log("error: ", fmt, ##__VA_ARGS__); \
}

#define log_alert(fmt, ...) \
{ \
	log("alert: ", fmt, ##__VA_ARGS__); \
}
