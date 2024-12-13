#include <stdio.h>
#include <stdlib.h>

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
	int capacity;
	int length;
};

int hash_function(int key, int capacity)
{
	return key % capacity;
}

/* get value for a given key */
int lookup(int key, struct hash_map *map)
{
	int index = hash_function(key, map->capacity);
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
	exit(1);
}

/* add/update hash map entry */
void add_entry(int key, int val, struct hash_map *map)
{
	int index = hash_function(key, map->capacity);
	struct node *current = map->entries[index];

	/* update value if already in map */
	while (current) {
		if (current->key == key) {
			current->val = val;
			return;
		}

		current = current->next;
	}

	/* key not in hash map: add new entry and insert at head */
	struct node *new_entry = malloc(sizeof(struct node));
	new_entry->key = key;
	new_entry->val = val;
	new_entry->next = map->entries[index];
	map->entries[index] = new_entry;
	map->length++;
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
	int index = hash_function(key, map->capacity);
	struct node **indirect = &map->entries[index];
	struct node *deleted;

	while ((*indirect)->key != key)
		indirect = &(*indirect)->next;

	deleted = *(indirect);
	*indirect = (*indirect)->next;
	free(deleted);
}

int main(int argc, char *argv[])
{
	/* initialise hash map */
	struct hash_map *map = malloc(sizeof(struct hash_map));
	map->capacity = 10;
	map->length = 0;
	map->entries = calloc((map->capacity), sizeof(struct node));

	add_entry(10, 20, map);
	add_entry(20, 40, map);
	add_entry(30, 60, map);

	printf("value of key %d = %d\n", 20, lookup(20, map));
	printf("value of key %d = %d\n", 10, lookup(10, map));
	printf("value of key %d = %d\n", 30, lookup(30, map));

	del_entry(20, map);
	add_entry(40, 80, map);

	printf("value of key %d = %d\n", 40, lookup(40, map));

	/* cleanup */
	for (int i = 0; i < map->capacity; i++) {
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
