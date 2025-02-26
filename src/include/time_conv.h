#ifndef __TIME_CONV_H
#define __TIME_CONV_H

#include <time.h>
#include <sys/sysinfo.h>

/* 1 second = 10^9 nanoseconds */
#define NS_PER_SEC 1000000000UL

void get_clock_time(struct timespec *time);
void time_to_str(time_t time, char *time_string, int size, char *format);
struct timespec time_diff(struct timespec *start, struct timespec *end);
void update_total_time(struct timespec *start, struct timespec *end,
		unsigned long *total_time);

unsigned long packet_rate(unsigned long *total_packets, unsigned long *total_time);

#endif
