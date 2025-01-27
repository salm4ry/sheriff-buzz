#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/ip.h>
#include <arpa/inet.h>


int main(int argc, char *argv[])
{
    __u32 ip, mask;
    struct in_addr addr;
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
    bits = inet_net_pton(AF_INET, cidr, &addr, sizeof(addr));
    mask = htonl(~(bits == 32 ? 0 : ~0U >> bits));

    inet_ntop(AF_INET, &addr.s_addr, network_str, sizeof(network_str));
    inet_ntop(AF_INET, &mask, mask_str, sizeof(mask_str));

    printf("bits: %d, addr: %s, mask: %s\n",
            bits, network_str, mask_str);

    /*
    printf("IP %s in subnet %s = %d\n", ip_str, cidr,
            (ip & network) == (ip & mask));
     */

    return EXIT_SUCCESS;
}
