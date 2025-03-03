#include <stdio.h>
#include "../src/include/bpf_common.h"

int main(int argc, char *argv[])
{
	printf("sizeof(xdp_rb_event) = %ld\n", sizeof(struct xdp_rb_event));
	return 0;
}
