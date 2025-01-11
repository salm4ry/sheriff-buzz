#define MAX_LOG_MSG 512

/*
#define log_debug(fmt, ...) \
	fprintf(LOG, fmt, ##__VA_ARGS__); \
	fflush(LOG)

#define log_alert(fmt, ...) \
	fprintf(LOG, fmt, ##__VA_ARGS__); \
	fflush(LOG)

#define log_error(fmt, ...) \
	fprintf(LOG, fmt, ##__VA_ARGS__); \
	fflush(LOG)
*/

#define make_msg(msg, fmt, ...) \
	snprintf(msg, MAX_LOG_MSG, fmt, ##__VA_ARGS__);

#define log_debug(fmt, ...) \
{ \
	char *msg = malloc(MAX_LOG_MSG * sizeof(char)); \
	make_msg(msg, fmt, ##__VA_ARGS__); \
	fputs(msg, LOG); \
	/*
	fwrite(msg, sizeof(char), strlen(msg), LOG); \
	fflush(LOG); \
	*/ \
	free(msg); \
}

#define log_alert(fmt, ...) \
{ \
	char *msg = malloc(MAX_LOG_MSG * sizeof(char)); \
	make_msg(msg, fmt, ##__VA_ARGS__); \
	fputs(msg, LOG); \
	/*
	fwrite(msg, sizeof(char), strlen(msg), LOG); \
	fflush(LOG); \
	*/ \
	free(msg); \
}

#define log_error(fmt, ...) \
{ \
	char *msg = malloc(MAX_LOG_MSG * sizeof(char)); \
	make_msg(msg, fmt, ##__VA_ARGS__); \
	fputs(msg, LOG); \
	/*
	fwrite(msg, sizeof(char), strlen(msg), LOG); \
	fflush(LOG); \
	*/ \
	free(msg); \
}
