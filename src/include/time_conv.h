#ifndef __TIME_CONV_H
#define __TIME_CONV_H

#include <time.h>
#include <sys/sysinfo.h>

#define NANO .000000001
#define REV_NANO 1000000000

long get_uptime();
time_t get_boot_time();
void get_clock_time(struct timespec *time);
time_t ktime_to_real(unsigned long long ktime);

void time_to_str(time_t time, char *time_string, int size, char *format);
struct timespec time_diff(struct timespec *start, struct timespec *end);
void update_total_time(struct timespec *start, struct timespec *end,
		unsigned long *total_time);

unsigned long packet_rate(unsigned long *total_packets, unsigned long *total_time);

#endif
