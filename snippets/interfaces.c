#include <stdio.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    struct ifaddrs *current_address, *addresses;
    if (getifaddrs(&addresses) == -1) {
        perror("getifaddrs");
        exit(errno);
    }


    /* list network interfaces
     * adapted from: https://www.cyberithub.com/list-network-interfaces
     */
    current_address = addresses;
    while (current_address) {
        sa_family_t family = current_address->ifa_addr->sa_family;
        if (family == AF_INET) {
            printf("interface: %s\n", current_address->ifa_name);
        }

        current_address = current_address->ifa_next;
    }

    /* TODO possibly use /proc/net/route */

    freeifaddrs(addresses);
    return EXIT_SUCCESS;
}
