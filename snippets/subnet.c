#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/ip.h>
#include <arpa/inet.h>


int main(int argc, char *argv[])
{
    __u32 ip, network, mask;
    char *ip_str, *network_str, *mask_str;

    if (argc != 4) {
        printf("usage: %s <ip> <network> <mask>\n", argv[0]);
        return EXIT_FAILURE;
    }

    ip_str = argv[1];
    network_str = argv[2];
    mask_str = argv[3];

    inet_pton(AF_INET, ip_str, &ip);
    inet_pton(AF_INET, network_str, &network);
    inet_pton(AF_INET, mask_str, &mask);

    printf("network: %s, mask: %s\n", network_str, mask_str);
    printf("IP %s in subnet = %d\n", ip_str, (ip & network) == (ip & mask));

    return EXIT_SUCCESS;
}
