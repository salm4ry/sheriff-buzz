#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/queue.h>
#include <pthread.h>

/**
 * work queue implementation using tailq and a single mutex, in addition to a
 * pthread_cond_t for event-based programming
 */

#define MAX_QUEUE_SIZE 100

struct log_item {
	int alert_type;
	int key;
	int value;
};

struct queue_entry {
	struct log_item *item;
	TAILQ_ENTRY(queue_entry) entries;
};

struct thread_args {
	struct work_queue *queue_head;
	pthread_mutex_t *queue_lock;
	pthread_cond_t *queue_cond;
};

TAILQ_HEAD(work_queue, queue_entry);


int queue_size(struct work_queue *head)
{
	struct queue_entry *current = NULL;
	int size = 0;

	TAILQ_FOREACH(current, head, entries)
		size++;

	return size;
}

int queue_full(struct work_queue *head)
{
	return queue_size(head) >= MAX_QUEUE_SIZE;
}

int queue_work(struct work_queue *queue, pthread_mutex_t *queue_lock,
		pthread_cond_t *queue_cond, int alert_type, int key, int value)
{
	/* don't add if queue full */
	if (queue_full(queue)) {
		return 1;
	}

	struct log_item *new_item = malloc(sizeof(struct log_item));
	struct queue_entry *new_entry = malloc(sizeof(struct queue_entry));
	new_item->alert_type = alert_type;
	new_item->key = key;
	new_item->value = value;

	new_entry->item = new_item;

	pthread_mutex_lock(queue_lock);
	TAILQ_INSERT_TAIL(queue, new_entry, entries);
#ifdef DEBUG
	printf("sending signal -> queued task %d\n", new_item->alert_type+1);
#endif

	/* send signal to worker thread to indicate queue is nonempty
	 *
	 * NOTE: since we only have one worker thread, using pthread_cond_signal()
	 * is more efficient than the pthread_cond_broadcast(), which works for
	 * multiple waiting threads
	 * */
	pthread_cond_signal(queue_cond);
	pthread_mutex_unlock(queue_lock);

	return 0;
}

/* int log_alert(PGconn *db_conn, char *fingerprint, int alert_type, struct key *key, struct value *value) */
int log_alert(int alert_type, int key, int value)
{
	printf("thread: alert type: %d, key: %d, value: %d\n",
			alert_type, key, value);
	return 0;
}

void thread_work(void *args)
{
	struct thread_args *ctx = args;
	struct work_queue *queue_head = ctx->queue_head;
	pthread_mutex_t *queue_lock = ctx->queue_lock;
	pthread_cond_t *queue_cond = ctx->queue_cond;

	struct queue_entry *current = NULL;
	int last = 0;

	while (1) {
		pthread_mutex_lock(queue_lock);
#ifdef DEBUG
		printf("waiting for entries...\n");
#endif
		while (TAILQ_EMPTY(queue_head)) {
			pthread_cond_wait(queue_cond, queue_lock);
		}

		/* grab new entry and remove from queue */
		current = TAILQ_FIRST(queue_head);
		TAILQ_REMOVE(queue_head, current, entries);
		pthread_mutex_unlock(queue_lock);

		/* act on item */
		log_alert(current->item->alert_type,
				  current->item->key,
				  current->item->value);

		/* exit if this is the last entry */
		last = current->item->alert_type == MAX_QUEUE_SIZE-1;
		free(current->item);
		free(current);

		if (last) {
			return;
		}
	}
}

int main(int argc, char *argv[])
{
	int res;
	pthread_t worker_thread;
	struct thread_args args;

	struct work_queue queue_head;
	pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

	srand(0);

	TAILQ_INIT(&queue_head);

	/* set up thread arguments */
	args.queue_head = &queue_head;
	args.queue_lock = &queue_lock;
	args.queue_cond = &queue_cond;

	printf("queue size = %d\n", queue_size(&queue_head));

	res = pthread_create(&worker_thread, NULL, (void *(*)(void *)) thread_work, &args);
	if (res != 0) {
		perror(strerror(errno));
	}

	/* queue work after starting thread */
	for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
		queue_work(&queue_head, &queue_lock, &queue_cond, i, i*2, i*3);
		/* random sleep (constant seed to match work_queue) */
		sleep(rand() % 10);
	}

	res = pthread_join(worker_thread, NULL);
	if (res != 0) {
		fprintf(stderr, "pthread_join failed\n");
		return 1;
	}

	return 0;
}
