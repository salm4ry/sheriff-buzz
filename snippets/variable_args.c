#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <string.h>
#include <time.h>
#include <stdarg.h>

#define MAX_PREFIX 28
#define MAX_TIME_STR 20
#define MAX_LOG_MSG 512

const char *TIME_FMT = "%Y-%m-%d %H-%M-%S";

void make_prefix(char *prefix, char *base)
{
	char time_str[MAX_TIME_STR];
	time_t current_time = time(NULL);
	struct tm tm;

	tm = *localtime(&current_time);
	strftime(time_str, MAX_TIME_STR, TIME_FMT, &tm);
	snprintf(prefix, MAX_PREFIX, "%s %s", time_str, base);
}

void log_to_file(char *prefix, char *fmt, va_list args)
{
	/* NOTE: 'v' versions take va_args lists */
	char *msg = malloc(MAX_LOG_MSG * sizeof(char));
	char *new_fmt = malloc(MAX_LOG_MSG * sizeof(char));

	if (!msg || !new_fmt) {
		perror("malloc");
		exit(errno);
	}

	strncpy(new_fmt, prefix, MAX_LOG_MSG);
	strncat(new_fmt, fmt, MAX_LOG_MSG - (strlen(new_fmt)+1));
	vprintf(new_fmt, args);

	free(msg);
	free(new_fmt);
}

void log_debug(char *fmt, ...)
{
	va_list args;

	char prefix[MAX_PREFIX];
	make_prefix(prefix, "debug: ");

	va_start(args, fmt);
	log_to_file(prefix, fmt, args);
	va_end(args);
}

int main(int argc, char *argv[])
{
	log_debug("hello %s %d %c\n", "Salma", 12, 'z');
	return EXIT_SUCCESS;
}
