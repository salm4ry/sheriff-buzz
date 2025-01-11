#define pr_fmt(fmt) fmt

/* read more: https://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html */
#define pr_err(fmt, ...) \
	fprintf(stderr, pr_fmt(fmt), ##__VA_ARGS__)
