#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>

int main(int argc, char *argv[])
{
    struct ifaddrs *current_interface, *interfaces;
	char iface_addr[NI_MAXHOST], target_addr[NI_MAXHOST];
	sa_family_t family;
	int res;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <address>\n", argv[0]);
		return EXIT_FAILURE;
	}

    if (getifaddrs(&interfaces) == -1) {
        perror("getifaddrs");
        exit(errno);
    }

	strncpy(target_addr, argv[1], sizeof(target_addr));

    current_interface = interfaces;
    while (current_interface) {
        family = current_interface->ifa_addr->sa_family;

        if (family == AF_INET) {
			res = getnameinfo(current_interface->ifa_addr, sizeof(struct sockaddr_in),
					iface_addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (res != 0) {
				fprintf(stderr, "getnameinfo: %s\n", gai_strerror(res));
				exit(res);
			}

			if (strncmp(target_addr, iface_addr, NI_MAXHOST) == 0) {
				printf("interface %s has address %s\n",
						current_interface->ifa_name, iface_addr);
				freeifaddrs(interfaces);
				exit(EXIT_SUCCESS);
			}
        }

        current_interface = current_interface->ifa_next;
    }

	/* interface not found */
	printf("no interface found with address %s\n", target_addr);

    freeifaddrs(interfaces);
    return EXIT_SUCCESS;
}
