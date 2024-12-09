#include <stdio.h>

/* based on struct va_format in printk.h
struct format_str {
	const char *format;
	va_list args;
};
*/

#define pr_fmt(fmt) fmt

/* read more: https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html */
#define pr_err(fmt, ...) \
	fprintf(stderr, pr_fmt(fmt), ##__VA_ARGS__)
