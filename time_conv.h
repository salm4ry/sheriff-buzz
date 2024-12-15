#include <stdio.h>
#include <stdlib.h>

#include <math.h>
#include <time.h>
#include <sys/sysinfo.h>

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
time_t ktime_to_real(unsigned long long ktime)
{
	time_t boot_time = get_boot_time();
	unsigned long long ktime_seconds = ktime / pow(10,9);
	return (time_t) (boot_time + ktime_seconds);
}

void time_to_str(time_t time, char *timestamp)
{
	struct tm *tm;
	tm = localtime(&time);
	strftime(timestamp, sizeof(timestamp), "%H:%M", tm);
}
