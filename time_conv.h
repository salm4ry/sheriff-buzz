#include <stdio.h>
#include <stdlib.h>

#include <time.h>
#include <sys/sysinfo.h>

#define NANO .000000001

/* get system uptime */
long get_uptime()
{
	struct sysinfo info;
	int res = sysinfo(&info);
	if (res) {
		fprintf(stderr, "error retrieving sysinfo\n");
		exit(1);
	}
	return info.uptime;
}

/* get time system booted at */
time_t get_boot_time()
{
	time_t current_time;
	time(&current_time);

	return current_time - get_uptime();
}

/* calculate real time from nanoseconds since boot */
inline time_t ktime_to_real(unsigned long long ktime)
{
	unsigned long long ktime_seconds = ktime * NANO;
	time_t boot_time = get_boot_time();
	return (time_t) (boot_time + ktime_seconds);
}

void time_to_str(time_t time, char *time_string, int size, char *format)
{
	struct tm *tm;
	tm = localtime(&time);
	strftime(time_string, size, format, tm);
}
