#include <stdio.h>
#include <stdarg.h>

#ifndef _pr_h
#define _pr_h

/* read more: https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html */
void pr_err(char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}
#endif
