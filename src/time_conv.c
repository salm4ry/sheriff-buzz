#include <time.h>
#include <sys/sysinfo.h>

#include "include/time_conv.h"

void get_clock_time(struct timespec *time)
{
	clock_gettime(CLOCK_MONOTONIC, time);
}

void time_to_str(time_t time, char *time_string, int size, char *format)
{
	struct tm *tm;
	tm = localtime(&time);
	strftime(time_string, size, format, tm);
}

struct timespec time_diff(struct timespec *start, struct timespec *end)
{
	/* tv_nsec describes nanoseconds within the current second */
	struct timespec res;

	if ((end->tv_nsec - start->tv_nsec) < 0) {
		/* TODO better explanation
		 * go back into previous second to calculate difference */
		res.tv_sec = end->tv_sec - start->tv_sec - 1;
		res.tv_nsec = (end->tv_nsec - start->tv_nsec) + NS_PER_SEC;
	} else {
		res.tv_sec = end->tv_sec - start->tv_sec;
		res.tv_nsec = end->tv_nsec - start->tv_nsec;
	}

	return res;
}

void update_total_time(struct timespec *start, struct timespec *end,
		       unsigned long *total_time)
{
	struct timespec delta = time_diff(start, end);
	/* TODO do we need nanosecond precision in time calculations? */
	*total_time += (delta.tv_sec * NS_PER_SEC) + delta.tv_nsec;
}

/*
 * Calculate number of packets processed per second
 * - total_packets: total packet count
 * - total_time: total packet processing time
 */
unsigned long packet_rate(unsigned long *total_packets, unsigned long *total_time)
{
	/* TODO do we need nanosecond precision in time calculations? */
	return (*total_packets * NS_PER_SEC) / *total_time;
}
