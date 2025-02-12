#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>
#include <signal.h>

#define MAX_BUF 128

void handler(int signum)
{
	char buf[MAX_BUF];
	snprintf(buf, MAX_BUF, "%d handled SIGUSR1\n", gettid());
	write(STDOUT_FILENO, buf, strlen(buf)+1);
}

void thread_work(void *arg)
{
	printf("thread created\n");

	while (1) {
		printf("worker thread (%d) %ld\n", gettid(), time(NULL));
		// pause();
		sleep(1);
	}
}

int main(int argc, char *argv[])
{
	struct sigaction act;
	pthread_t thread;
	int res;

	act.sa_handler = handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;

	if (sigaction(SIGUSR1, &act, NULL) == -1) {
		perror("sigaction");
		return EXIT_FAILURE;
	}

	printf("creating thread\n");
	res = pthread_create(&thread, NULL, (void *(*)(void *)) thread_work, NULL);
	if (res != 0) {
		perror("pthread_create");
		return EXIT_FAILURE;
	}

	while (1) {
		printf("main thread (%d) %ld\n", gettid(), time(NULL));
		// pause();
		sleep(1);
	}

	return EXIT_SUCCESS;
}
