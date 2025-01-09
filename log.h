#define log_fmt(fmt) fmt

#define log_debug(fmt, ...) \
	fprintf(LOG, log_fmt(fmt), ##__VA_ARGS__); \
	fflush(LOG)

#define log_alert(fmt, ...) \
	fprintf(LOG, log_fmt(fmt), ##__VA_ARGS__); \
	fflush(LOG)

#define log_error(fmt, ...) \
	fprintf(LOG, log_fmt(fmt), ##__VA_ARGS__); \
	fflush(LOG)


enum alert_type {
	XMAS_SCAN = 1,
	FIN_SCAN = 2,
	NULL_SCAN = 3,
	BASIC_SCAN = 4
};
