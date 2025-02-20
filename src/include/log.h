#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

#define MAX_LOG_MSG 512
#define MAX_TIME_STR 20
#define MAX_PREFIX 28
#define TIME_FMT "%Y-%m-%d %H-%M-%S"

FILE *LOG;

#ifndef _log_h
#define _log_h

/* TODO inline? */

char *make_prefix(char *base)
{
	char time_str[MAX_TIME_STR];
	time_t current_time;
	struct tm tm;

    char *prefix = malloc(MAX_PREFIX * sizeof(char));
    if (!prefix) {
        perror("malloc");
        exit(errno);
    }

    current_time = time(NULL);
	localtime_r(&current_time, &tm);
	strftime(time_str, MAX_TIME_STR, TIME_FMT, &tm);
	snprintf(prefix, MAX_PREFIX, "%s %s", time_str, base);

    return prefix;
}

void make_msg(char *msg, char *fmt, va_list args)
{
    vsnprintf(msg, MAX_LOG_MSG, fmt, args);
}

void log_to_file(char *prefix, char *fmt, va_list args)
{
    char *msg = malloc(MAX_LOG_MSG * sizeof(char));
    char *new_fmt = malloc(MAX_LOG_MSG * sizeof(char));

    if (!msg || !new_fmt) {
        perror("malloc");
        exit(errno);
    }

    strncpy(new_fmt, prefix, MAX_LOG_MSG);
    strncat(new_fmt, fmt, MAX_LOG_MSG - (strlen(new_fmt)+1));
    make_msg(msg, new_fmt, args);
    fputs(msg, LOG);
    fflush(LOG);

    free(msg);
    free(new_fmt);
}

void log_with_prefix(char *log_type, char *fmt, va_list args)
{
    char *prefix = make_prefix(log_type);
    log_to_file(prefix, fmt, args);
    free(prefix);
}

/*
#ifdef DEBUG
    void log_debug(char *fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        log_with_prefix("debug: ", fmt, args);
        va_end(args);
    }
#else
*/
   void log_debug(char *fmt, ...) { }
// #endif

void log_info(char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_with_prefix("info: ", fmt, args);
    va_end(args);
}

void log_error(char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_with_prefix("error: ", fmt, args);
    va_end(args);
}

/* TODO check for dry run */
void log_alert(char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_with_prefix("alert: ", fmt, args);
    va_end(args);
}
#endif
