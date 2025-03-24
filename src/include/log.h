#ifndef __LOG_INTERFACE
#define __LOG_INTERFACE

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#define MAX_LOG_MSG 512
#define MAX_TIME_STR 20
#define MAX_PREFIX 28
#define TIME_FMT "%Y-%m-%d %H-%M-%S"

#define p_error(msg) do { \
    fprintf(stderr, "%s:%s:%d: %s: %s\n", __FILE__, __func__, __LINE__, (msg), strerror(errno)); \
} while(0)

/* print to stderr */
void pr_err(char *fmt, ...);

/* logging helpers */
char *format_prefix(char *base);
void format_msg(char *msg, char *fmt, va_list args);
void log_msg(FILE *file, char *prefix, char *fmt, va_list args);
void log_with_prefix(FILE *file, char *log_type, char *fmt, va_list args);

/* log levels */
void log_debug(FILE *file, char *fmt, ...);
void log_info(FILE *file, char *fmt, ...);
void log_error(FILE *file, char *fmt, ...);
void log_alert(FILE *file, char *fmt, ...);

#endif
