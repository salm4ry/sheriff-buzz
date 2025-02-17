#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("usage: %s <IPv4 address>\n", argv[0]);
		return 1;
	}

	char ip_str[16];
	in_addr_t ip = atol(argv[1]);

	/* convert network-order binary data to xxx.xxx.xxx.xxx */
	inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
	printf("%u -> %s\n", ip, ip_str);

	return 0;
}
