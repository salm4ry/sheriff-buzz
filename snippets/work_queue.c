#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>


#define MAX_QUEUE_SIZE 4096

struct log_item {
	pthread_rwlock_t state_lock;
	int alert_type;
	int key;
	int value;
	bool busy;
};

struct queue_entry {
	struct log_item *item;
	pthread_rwlock_t item_lock;
};

struct work_queue {
	int size;
	struct queue_entry entries[MAX_QUEUE_SIZE];
	pthread_rwlock_t size_lock;
};

struct work_queue queue;

int queue_work(struct work_queue *queue, int alert_type, int key, int value)
{
	/* don't add if queue full */
	if (queue->size == MAX_QUEUE_SIZE) {
		return 1;
	}

	struct log_item *new_item = malloc(sizeof(struct log_item));
	new_item->alert_type = alert_type;
	new_item->key = key;
	new_item->value = value;
	new_item->busy = false;
	pthread_rwlock_init(&new_item->state_lock, NULL);

	/* add to first available space */
	for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
		if (queue->entries[i].item == NULL) {
			queue->entries[i].item = new_item;
			pthread_rwlock_init(&queue->entries[i].item_lock, NULL);
			break;
		}
	}

	pthread_rwlock_wrlock(&queue->size_lock);
	queue->size++;
	pthread_rwlock_unlock(&queue->size_lock);

	return 0;
}

int remove_queue_item(struct work_queue *queue, struct queue_entry *entry)
{
#ifdef DEBUG
	printf("thread %ld waiting for queue wrlock\n", pthread_self());
#endif

	pthread_rwlock_wrlock(&entry->item_lock);

#ifdef DEBUG
	printf("thread %ld removing\n", pthread_self());
#endif

	pthread_rwlock_wrlock(&queue->size_lock);
	queue->size--;
	pthread_rwlock_unlock(&queue->size_lock);

	/* pthread_rwlock_destroy(&entry->item->state_lock); */
	free(entry->item);
	entry->item = NULL;
	pthread_rwlock_unlock(&entry->item_lock);
	return 0;
}

void destroy_queue(struct work_queue *queue)
{
	for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
		if (queue->entries[i].item) {
			free(queue->entries[i].item);
		}
	}
}

/* int log_alert(PGconn *db_conn, char *fingerprint, int alert_type, struct key *key, struct value *value) */
int log_alert(int alert_type, int key, int value)
{
	printf("thread: alert type: %d, key: %d, value: %d\n",
			alert_type, key, value);
	return 0;
}

void thread_work()
{
	struct queue_entry *current_item;

#ifdef DEBUG
	printf("thread %ld initial queue size = %d\n", pthread_self(), queue.size);
#endif
	while (true) {
#ifdef DEBUG
		printf("thread %ld queue size = %d\n", pthread_self(), queue.size);
#endif
		for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
#ifdef DEBUG
			printf("thread %ld updated queue size = %d\n", pthread_self(), queue.size);
#endif

			pthread_rwlock_rdlock(&queue.size_lock);
			if (queue.size == 0) {
				return;
			}
			pthread_rwlock_unlock(&queue.size_lock);

			/*
			printf("thread %ld trying to get queue rdlock\n", pthread_self());
			*/
			current_item = &queue.entries[i];
			pthread_rwlock_rdlock(&current_item->item_lock);
			if (current_item->item) {
				/*
				printf("thread %ld waiting for item %d rdlock\n",
						pthread_self(), i);
				*/

				/* set busy to true */
				if (pthread_rwlock_trywrlock(&current_item->item->state_lock)) {
#ifdef DEBUG
					printf("couldn't get item %d wrlock\n", i);
#endif
					pthread_rwlock_unlock(&current_item->item_lock);
					continue;
				};
				if (current_item->item->busy) {
#ifdef DEBUG
					printf("thread %ld, item %d busy already true\n",
							pthread_self(), i);
#endif
					pthread_rwlock_unlock(&current_item->item->state_lock);
					pthread_rwlock_unlock(&current_item->item_lock);
					continue;
				}

#ifdef DEBUG
				printf("thread %ld, setting item %d busy to true\n",
						pthread_self(), i);
#endif
				current_item->item->busy = true;
				pthread_rwlock_unlock(&current_item->item->state_lock);
				pthread_rwlock_unlock(&current_item->item_lock);

				/* act on item */
				log_alert(current_item->item->alert_type,
						  current_item->item->key, 
						  current_item->item->value);

				/* remove item from queue */
#ifdef DEBUG
				printf("thread %ld trying to remove item %d\n", 
						pthread_self(), i);
#endif
				remove_queue_item(&queue, current_item);
#ifdef DEBUG
				printf("thread %ld removed item %d\n", 
						pthread_self(), i);
#endif
			} else {
#ifdef DEBUG
				printf("thread %ld: item %d is null\n", pthread_self(), i);
#endif
				pthread_rwlock_unlock(&current_item->item_lock);
			}
		}
	}
}


int main(int argc, char *argv[])
{
	int res, num_threads;
	pthread_t *threads;

	if (argc != 2) {
		printf("usage: %s <num_threads>\n", argv[0]);
		return 1;
	}

	num_threads = atoi(argv[1]);
	if (num_threads == 0) {
		printf("error: invalid number of threads %d\n", num_threads);
		return 1;
	}

	threads = calloc(num_threads, sizeof(*threads));
	printf("sizeof(struct queue_item) = %ld, sizeof(struct work_queue) = %ld\n",
			sizeof(struct queue_entry), sizeof(struct work_queue));

	for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
		queue.entries[i].item = NULL;
	}

	queue.size = 0;
	pthread_rwlock_init(&queue.size_lock, NULL);

	for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
		queue_work(&queue, i, i*2, i*3);
	}

#ifdef DEBUG
	for (int i = 0; i < MAX_QUEUE_SIZE; i++) {
		if (queue.entries[i].item) {
			printf("main: item %d: {%d, %d, %d}\n",
					i, queue.entries[i].item->alert_type, 
					queue.entries[i].item->key, queue.entries[i].item->value);
		}
	}
#endif

	printf("queue size = %d\n", queue.size);

	for (int i = 0; i < num_threads; i++) {
		res = pthread_create(&threads[i], NULL, (void *) thread_work, NULL);
		if (res != 0) {
			fprintf(stderr, "pthread_create failed\n");
			return 1;
		}
	}

	for (int i = 0; i < num_threads; i++) {
		res = pthread_join(threads[i], NULL);
		if (res != 0) {
			fprintf(stderr, "pthread_join failed\n");
			return 1;
		}
	}

	free(threads);
	destroy_queue(&queue);
	return 0;
}
