#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/ip.h>
#include <arpa/inet.h>


int main(int argc, char *argv[])
{
    __u32 ip, mask, network = 0;
    char *ip_str, *cidr;
    char mask_str[17], network_str[17];
    int bits;

    if (argc != 3) {
        printf("usage: %s <ip> <cidr>\n", argv[0]);
        return EXIT_FAILURE;
    }

    ip_str = argv[1];
    cidr = argv[2];

    inet_pton(AF_INET, ip_str, &ip);
    bits = inet_net_pton(AF_INET, cidr, &network, sizeof(network));

    /* convert number of bits to subnet mask (based on ipcalc implementation) */
    mask = htonl(~((1 << (32 - bits)) - 1));
    /* convert address to network address with bitwise AND */
    network &= mask;

    inet_ntop(AF_INET, &network, network_str, sizeof(network_str));
    inet_ntop(AF_INET, &mask, mask_str, sizeof(mask_str));

    printf("bits: %d, network addr: %s, mask: %s\n",
            bits, network_str, mask_str);

    printf("IP %s in subnet %s = %d\n", ip_str, cidr,
            (ip & network) == (ip & mask));

    return EXIT_SUCCESS;
}
