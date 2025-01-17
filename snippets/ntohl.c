#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("usage: %s <IPv4 address>\n", argv[0]);
		return 1;
	}

	/* network (big-endian) to host (little-endian) byte order */
	printf("%s -> %u\n", argv[1], ntohl(atol(argv[1])));

	return 0;
}
