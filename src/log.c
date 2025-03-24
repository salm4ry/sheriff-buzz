#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

#include "include/log.h"

void pr_err(char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

/* TODO inline? */

char *format_prefix(char *base)
{
	char time_str[MAX_TIME_STR];
	time_t current_time;
	struct tm tm;

    char *prefix = malloc(MAX_PREFIX * sizeof(char));
    if (!prefix) {
        p_error("failed to allocate prefix");
        exit(errno);
    }

    current_time = time(NULL);
	localtime_r(&current_time, &tm);
	strftime(time_str, MAX_TIME_STR, TIME_FMT, &tm);
	snprintf(prefix, MAX_PREFIX, "%s %s", time_str, base);

    return prefix;
}

void format_msg(char *msg, char *fmt, va_list args)
{
    vsnprintf(msg, MAX_LOG_MSG, fmt, args);
}

void log_msg(FILE *file, char *prefix, char *fmt, va_list args)
{
    char *msg;
    char *new_fmt;

    msg = malloc(MAX_LOG_MSG * sizeof(char));
    if (!msg) {
        p_error("failed to allocate msg");
        exit(errno);
    }

    new_fmt = malloc(MAX_LOG_MSG * sizeof(char));
    if (!new_fmt) {
        p_error("failed to allocate new_fmt");
        exit(errno);
    }

    strncpy(new_fmt, prefix, MAX_LOG_MSG);
    strncat(new_fmt, fmt, MAX_LOG_MSG - (strlen(new_fmt)+1));
    format_msg(msg, new_fmt, args);
    fputs(msg, file);
    fflush(file);

    free(msg);
    free(new_fmt);
}

void log_with_prefix(FILE *file, char *log_type, char *fmt, va_list args)
{
    char *prefix = format_prefix(log_type);
    log_msg(file, prefix, fmt, args);
    free(prefix);
}

#ifdef DEBUG
    void log_debug(FILE *file, char *fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        log_with_prefix(file, "debug: ", fmt, args);
        va_end(args);
    }
#else
   void log_debug(FILE *file, char *fmt, ...) { }
#endif

void log_info(FILE *file, char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_with_prefix(file, "info: ", fmt, args);
    va_end(args);
}

void log_error(FILE *file, char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_with_prefix(file, "error: ", fmt, args);
    va_end(args);
}

/* TODO check for dry run */
void log_alert(FILE *file, char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_with_prefix(file, "alert: ", fmt, args);
    va_end(args);
}
