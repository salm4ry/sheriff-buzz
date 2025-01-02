#include <stdio.h>
#include <stdlib.h>

#define MAX_LENGTH 20

/* key-value pair
 *
 * (linked list to avoid collisions = separate chaining)
 * https://en.wikipedia.org/wiki/Hash_table#Collision_resolution
 */
struct node {
	int key;
	int val;
	struct node *next;
};

struct hash_map {
	struct node **entries;
	int num_slots;
	int length;
};

int hash_function(int key, int capacity)
{
	return key % capacity;
}

/* get value for a given key */
int lookup(int key, struct hash_map *map)
{
	int index = hash_function(key, map->num_slots);
	if (map->entries[index]) {
		struct node *current = map->entries[index];

		/* walk linked list to find key */
		while (current) {
			if (current->key == key) {
				return current->val;
			}

			current = current->next;
		}
	}

	/* not found */
	printf("key %d not found\n", key);
	return -1;
}

/* add/update hash map entry */
void add_entry(int key, int val, struct hash_map *map)
{
	int index = hash_function(key, map->num_slots);
	struct node *current = map->entries[index];

	/* update value if already in map */
	while (current) {
		if (current->key == key) {
			current->val = val;
			return;
		}

		current = current->next;
	}

	/* add if we don't go over the max */
	if (map->length < MAX_LENGTH) {
		/* key not in hash map: add new entry and insert at head */
		struct node *new_entry = malloc(sizeof(struct node));
		new_entry->key = key;
		new_entry->val = val;
		new_entry->next = map->entries[index];
		map->entries[index] = new_entry;
		map->length++;
	} else {
		printf("hash map full; cannot add key %d\n", key);
	}
}

/* delete hash map entry 
 *
 * based on:
 * https://www.ted.com/talks/linus_torvalds_the_mind_behind_linux (14:10)
 *
 * read more:
 * https://github.com/mkirchner/linked-list-good-taste
 */
void del_entry(int key, struct hash_map *map)
{
	int index = hash_function(key, map->num_slots);
	struct node **indirect = &map->entries[index];
	struct node *deleted;

	while ((*indirect)->key != key)
		indirect = &(*indirect)->next;

	deleted = *(indirect);
	*indirect = (*indirect)->next;
	free(deleted);

	/* update length */
	map->length--;
}

int main(int argc, char *argv[])
{
	/* initialise hash map */
	struct hash_map *map = malloc(sizeof(struct hash_map));
	map->num_slots = 5;
	map->length = 0;
	map->entries = calloc((map->num_slots), sizeof(struct node));

	for (int i = 0; i < 30; i++) {
		add_entry(i, 2*i, map);
	}

	for (int i = 0; i < 30; i++) {
		int val = lookup(i, map);
		if (val != -1)
			printf("value of key %d = %d\n", i, val);
	}

	del_entry(15, map);
	printf("deleted entry %d\n", 15);

	/* cleanup */
	for (int i = 0; i < map->num_slots; i++) {
		/* free linked list for each entry */
		struct node *head = map->entries[i];
		struct node *current;

		while (head) {
			current = head;
			head = head->next;
			free(current);
		}
	}
	free(map->entries);
	free(map);
}
