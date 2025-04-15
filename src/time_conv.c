/// @file

#include <time.h>
#include <sys/sysinfo.h>

#include "include/time_conv.h"

/**
 * @brief Get monotonic clock time
 * @param time output clock time
 */
void get_clock_time(struct timespec *time)
{
	clock_gettime(CLOCK_MONOTONIC, time);
}

/**
 * @brief Convert time_t to string
 * @param time time to convert
 * @param time_string output time string
 * @param size max size of time string
 * @param format time string format
 */
void time_to_str(time_t time, char *time_string, int size, char *format)
{
	struct tm *tm;
	tm = localtime(&time);
	strftime(time_string, size, format, tm);
}

/**
 * @brief Calculate the difference between two times (struct timespec)
 * @param start start time
 * @param end end time
 * @return Difference between start and end time
 */
struct timespec time_diff(struct timespec *start, struct timespec *end)
{
	/* tv_nsec describes nanoseconds within the current second */
	struct timespec res;

	if ((end->tv_nsec - start->tv_nsec) < 0) {
		/* go back into previous second to calculate difference */
		res.tv_sec = end->tv_sec - start->tv_sec - 1;
		res.tv_nsec = (end->tv_nsec - start->tv_nsec) + NS_PER_SEC;
	} else {
		res.tv_sec = end->tv_sec - start->tv_sec;
		res.tv_nsec = end->tv_nsec - start->tv_nsec;
	}

	return res;
}

/**
 * @brief Update the total time based on time elapsed
 * @param start start time
 * @param end end time
 * @param total_time total time value to update
 * @details Use time_diff() on start and end, then add to total_time
 */
void update_total_time(struct timespec *start, struct timespec *end,
		       unsigned long *total_time)
{
	struct timespec delta = time_diff(start, end);
	*total_time += (delta.tv_sec * NS_PER_SEC) + delta.tv_nsec;
}

/**
 * @brief Calculate number of packets processed per second
 * @param total_packets total packet count
 * @param total_time total packet processing time
 * @return Number of packets processed per second on success, 0 on failure
 * (total_time = 0)
 */
unsigned long packet_rate(unsigned long *total_packets, unsigned long *total_time)
{
	if (*total_time == 0) {
		/* handle division by 0 */
		return 0;
	}
	return (*total_packets * NS_PER_SEC) / *total_time;
}
