#include <stdio.h>
#include <stdint.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#include <sys/sysinfo.h>
#include <time.h>
#include <math.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if_link.h>

#include <bpf/libbpf.h>

#include "pr.h"
#include "detect_scan.h"

struct bpf_object *obj;
uint32_t xdp_flags;
int ifindex;
struct ring_buffer *rb = NULL;
int err;

PGconn *db_conn;

int *common_ports = NULL; /* store top 1000 TCP ports */
const int NUM_COMMON_PORTS = 1000;
const int MAX_ADDR_LEN = 16;

void cleanup()
{
	/* XDP detach on SIGTERM */
	bpf_xdp_detach(ifindex, xdp_flags, NULL);
	ring_buffer__free(rb);
	free(common_ports);
}

/* TODO switch signal() to sigaction()
void handle_signal(int signum) {
	if (signum == SIGINT || signum == SIGTERM) {
		signal(signum, cleanup);
	}
	return;
}
*/


int load_bpf_obj(const char *filename)

{
	int prog_fd = -1;
	int err;

	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		pr_err("open object file failed: %s\n",
				strerror(errno));
		return -1;
	}

	struct bpf_program *prog = bpf_object__next_program(obj, NULL);
	if (prog == NULL) {
		pr_err("find program in object failed: %s\n",
				strerror(errno));
		return -1;
	}

	/* set to XDP */
	if (bpf_program__set_type(prog, BPF_PROG_TYPE_XDP) < 0) {
		pr_err("set bpf type to xdp failed: %s\n", strerror(errno));
		return -1;
	}

	err = bpf_object__load(obj);
	if (err) {
		pr_err("load bpf object failed: %s\n", strerror(errno));
		return -1;
	}

	prog_fd = bpf_program__fd(prog);
	if (!prog_fd) {
		pr_err("error loading bpf object file(%s) (%d): %s\n",
				filename, err, strerror(-err));
	}

	return prog_fd;
}

char *procnum_to_str(int protocol)
{
	switch (protocol) {
		case 1:
			return "ICMP";
		case 6:
			return "TCP";
		case 17:
			return "UDP";
		case 0:
			/* ring buffer contains 0 for anything else */
			return "other";
		default:
			/* we hopefully shouldn't see this! */
			return "invalid";
	}
}

void ip_to_str(long address, char buffer[]) {
	address = ntohl(address);

	/* NOTE specific to IPv4, would need to add another case (and maximum
	 * length) for IPv6 addresses (AF_INET6) */
	inet_ntop(AF_INET, &address, buffer, MAX_ADDR_LEN);
}

/* get system uptime */
long get_uptime()
{
	struct sysinfo info;
	int res = sysinfo(&info);
	if (res) {
		fprintf(stderr, "error retrieving sysinfo\n");
		exit(1);
	}
	return info.uptime;
}

/* get time system booted at */
time_t get_boot_time()
{
	time_t current_time;
	time(&current_time);

	return current_time - get_uptime();
}

/* calculate real time from nanoseconds since boot */
time_t ktime_to_real(unsigned long long ktime)
{
	time_t boot_time = get_boot_time();
	unsigned long long ktime_seconds = ktime / pow(10,9);
	return (time_t) (boot_time + ktime_seconds);
}

void time_to_str(time_t time, char *timestamp)
{
	struct tm *tm;
	tm = localtime(&time);
	strftime(timestamp, sizeof(timestamp), "%H:%M", tm);
}

/* get port list from comma-separated file */
int *get_port_list(char *filename, int num_ports) {
	FILE *fptr;
	char *buffer = NULL;
	size_t bufsize;

	char *token;
	char *delim = ",";
	int index = 0;
	int *port_list = NULL;

	fptr = fopen(filename, "r");

	if (fptr) {
		getline(&buffer, &bufsize, fptr);
		/* list of ports is comma-separated */
		token = strtok(buffer, delim);

		/* allocate memory for final port list */
		port_list = malloc(num_ports * sizeof(int));
		while (token) {
			port_list[index++] = atoi(token);
			token = strtok(NULL, delim);
		}
		free(buffer);
	} else {
		pr_err("error opening file %s\n", filename);
		exit(1);
	}

	/* close file */
	fclose(fptr);
	return port_list;
}


static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct rb_event *e = data;
	int old_port_count, new_port_count;
    char src_addr[MAX_ADDR_LEN], time_string[32];

    struct connection current_conn;
    struct packet current_packet;

    int db_res;

	/* extract data from IP and TCP headers */
	current_conn.src_ip = get_source_addr(&e->iph);
	ip_to_str(current_conn.src_ip, src_addr);

	current_conn.packet_count = e->count;

	/*
    db_res = edit_connection(db_conn, &current_conn);
    if (db_res) {
        cleanup();
        exit(1);
    }
	*/

	time_to_str(ktime_to_real(e->timestamp), time_string);
	printf("count: %d, timestamp: %lld -> %s\n",
			e->count, e->timestamp, time_string);

	/* TCP flags */
	current_packet.flags[FIN] = get_tcp_flag(&e->tcph, TCP_FLAG_FIN);
	current_packet.flags[SYN] = get_tcp_flag(&e->tcph, TCP_FLAG_SYN);
	current_packet.flags[RST] = get_tcp_flag(&e->tcph, TCP_FLAG_RST);
	current_packet.flags[PSH] = get_tcp_flag(&e->tcph, TCP_FLAG_PSH);
	current_packet.flags[ACK] = get_tcp_flag(&e->tcph, TCP_FLAG_ACK);
	current_packet.flags[URG] = get_tcp_flag(&e->tcph, TCP_FLAG_URG);
	current_packet.flags[ECE] = get_tcp_flag(&e->tcph, TCP_FLAG_ECE);
	current_packet.flags[CWR] = get_tcp_flag(&e->tcph, TCP_FLAG_CWR);

	/* TCP destination port */
	current_packet.dst_port = get_dst_port(&e->tcph);

	/*
    db_res = add_packet(db_conn, &current_conn, &current_packet);
    if (db_res) {
        printf("adding packet failed\n");
        cleanup();
        exit(1);
    }
	*/

	old_port_count = count_ports_scanned(&current_conn);
	current_conn.ports_scanned[current_packet.dst_port] = true;
	new_port_count = count_ports_scanned(&current_conn);

	if (new_port_count > old_port_count || current_packet.dst_port != 22) {
		printf("count: %d, dest_port: %d\n", e->count, current_packet.dst_port);
		printf("connection from %s: %d packets, %d ports\n",
			src_addr, current_conn.packet_count, new_port_count);
	}

	if (is_basic_scan(&current_conn, common_ports, NUM_COMMON_PORTS)) {
		printf("nmap (standard 1000 ports) detected from %s!\n", src_addr);
	}

	if (is_xmas_scan(&current_packet)) {
		printf("nmap Xmas scan detected from %s!\n", src_addr);
	}

	if (is_fin_scan(&current_packet)) {
		printf("nmap FIN scan detected from %s!\n", src_addr);
	}

	if (is_null_scan(&current_conn, &current_packet)) {
		printf("nmap null scan detected from %s!\n", src_addr);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct bpf_map *map = NULL;
	int prog_fd, map_fd;
	bool exiting = false;

	/* catch SIGINT (e.g. Ctrl+C, kill) */
	if (signal(SIGINT, cleanup) == SIG_ERR) {
		pr_err("error setting up signal handler\n");
		return 1;
	}

	if (signal(SIGTERM, cleanup) == SIG_ERR) {
		pr_err("error setting up signal handler\n");
		return 1;
	}

	/* check we have the second argument */
	if (argc < 2) {
		printf("usage: %s <interface name> [--skb-mode]\n", argv[0]);
		return 0;
	}

	prog_fd = load_bpf_obj("packet.bpf.o");
	if (prog_fd <= 0) {
		pr_err("error loading file: %s\n", "packet.bpf.o");
	}

	ifindex = if_nametoindex(argv[1]);
	xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;  /* from linux/if_link.h */

	/* set skb mode if third option present using bitwise OR */
	if (argc >= 3) {
		if (strncmp(argv[2], "--skb-mode", strlen(argv[2])) == 0) {
			xdp_flags |= XDP_FLAGS_SKB_MODE;
		} else {
		}
	}

	/* set up database */
	db_conn = connect_db("root", "packet_counter");
	create_tables(db_conn);

	common_ports = get_port_list("top-1000-tcp.txt", NUM_COMMON_PORTS);

	err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
	if (err < 0) {
		pr_err("error: ifindex  %d link set xdp fd failed %d: %s\n",
				ifindex, -err, strerror(-err));
		switch (-err) {
			case EBUSY:
			case EEXIST:
				pr_err("XDP already loaded on device %s\n",
						argv[1]);
				break;
			case ENOMEM:
			case EOPNOTSUPP:
				pr_err("native XDP not supported on device %s, try --skb-mode\n",
						argv[1]);
				break;
			default:
				break;
		}
		goto cleanup;
	}

	map = bpf_object__find_map_by_name(obj, "rb");
	if (!map) {
		pr_err("cannot find map by name: %s\n", "rb");
		goto cleanup;
	}
	map_fd = bpf_map__fd(map);

	rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		pr_err("failed to create ring buffer\n");
		goto cleanup;
	}

	/* poll the ring buffer every 2 seconds */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);

		/* EINTR = interrupted syscall */
		if (err == -EINTR) {
			err = 0;
			goto cleanup;
		}

		if (err < 0) {
			pr_err("error polling ring buffer: %d\n", err);
			goto cleanup;
		}
		/* sleep(2); */
	}

	return 0;

cleanup:
	bpf_xdp_detach(ifindex, xdp_flags, NULL);
	ring_buffer__free(rb);
	free(common_ports);
	return err < 0 ? err : 0;
}
