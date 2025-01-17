#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("usage: %s <IPv4 address>\n", argv[0]);
		return 1;
	}

	uint32_t dst = 0;

	/* convert xxx.xxx.xxx.xxx to network-order binary data */
	inet_pton(AF_INET, argv[1], &dst);
	printf("%s -> %u\n", argv[1], dst);

	return 0;
}
