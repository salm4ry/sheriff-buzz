#include <stdio.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if_link.h>

#include <bpf/libbpf.h>

#include <glib.h>
#include <postgresql/libpq-fe.h>

#include "packet.h"
#include "pr.h"
#include "detect_scan.h"
#include "time_conv.h"
#include "log.h"

struct bpf_object *obj;
uint32_t xdp_flags;
int ifindex;
struct ring_buffer *rb = NULL;
int err;

GHashTable *packet_table;

PGconn *db_conn;

int *common_ports = NULL; /* store top 1000 TCP ports */
const int NUM_COMMON_PORTS = 1000;
const int MAX_ADDR_LEN = 16;

bool exiting = false;

pthread_rwlock_t hash_table_lock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t db_lock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t exit_lock = PTHREAD_MUTEX_INITIALIZER;

pthread_t *threads;
int num_threads = 0;

void cleanup()
{
	/* redirect cleanup-related errors to /dev/null */
	freopen("/dev/null", "r", stderr);

	if (exiting) {
		return;
	}

	pthread_rwlock_wrlock(&exit_lock);
	exiting = true;
	pthread_rwlock_unlock(&exit_lock);

	bpf_xdp_detach(ifindex, xdp_flags, NULL);
	ring_buffer__free(rb);
	g_hash_table_destroy(packet_table);
	free(common_ports);

	int res;

	if (num_threads != 0) {
		for (int i = 0; i < num_threads; i++) {
			res = pthread_kill(threads[i], SIGKILL);
			if (res != 0) {
				pr_err("pthread kill failed\n");
			}
		}

		free(threads);
	}

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

/* get list of ports a given IP (and flag combination) has sent packets to */
bool *get_ports_scanned(long src_ip)
{
	bool *ports_scanned = malloc(NUM_PORTS * sizeof(bool));
	char **fingerprints = gen_port_fingerprints(src_ip);
	gboolean res;

	for (int i = 0; i < NUM_PORTS; i++) {
		pthread_rwlock_rdlock(&hash_table_lock);
		res = g_hash_table_contains(packet_table, (gconstpointer) fingerprints[i]);
		pthread_rwlock_unlock(&hash_table_lock);
		ports_scanned[i] = res;
		/* printf("%s: port %d -> %b\n", fingerprints[i], i, ports_scanned[i]); */
	}

	free_port_fingerprints(fingerprints);
	return ports_scanned;
}


static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct rb_event *e = data;
    char src_addr[MAX_ADDR_LEN], time_string[32];

	struct key current_packet;
	struct value new_val;
	char fingerprint[MAX_FINGERPRINT];
	gpointer res;

	/*
    struct connection current_conn;
    struct packet current_packet;
    int db_res;
	*/

	/* extract data from IP and TCP headers */

	/* source IP address */
	current_packet.src_ip = get_source_addr(&e->iph);

	/* destination TCP port */
	current_packet.dst_port = get_dst_port(&e->tcph);

	/* TCP flags */
	/*
	current_packet.flags[FIN] = get_tcp_flag(&e->tcph, TCP_FLAG_FIN);
	current_packet.flags[SYN] = get_tcp_flag(&e->tcph, TCP_FLAG_SYN);
	current_packet.flags[RST] = get_tcp_flag(&e->tcph, TCP_FLAG_RST);
	current_packet.flags[PSH] = get_tcp_flag(&e->tcph, TCP_FLAG_PSH);
	current_packet.flags[ACK] = get_tcp_flag(&e->tcph, TCP_FLAG_ACK);
	current_packet.flags[URG] = get_tcp_flag(&e->tcph, TCP_FLAG_URG);
	current_packet.flags[ECE] = get_tcp_flag(&e->tcph, TCP_FLAG_ECE);
	current_packet.flags[CWR] = get_tcp_flag(&e->tcph, TCP_FLAG_CWR);
	*/

	/*
    db_res = edit_connection(db_conn, &current_conn);
    if (db_res) {
        cleanup();
        exit(1);
    }
    db_res = add_packet(db_conn, &current_conn, &current_packet);
    if (db_res) {
        printf("adding packet failed\n");
        cleanup();
        exit(1);
    }
	*/

	/*
	if (is_basic_scan(&current_conn, common_ports, NUM_COMMON_PORTS)) {
		printf("nmap (standard 1000 ports) detected from %s!\n", src_addr);
	}
	*/

	ip_to_str(current_packet.src_ip, src_addr);
	time_to_str(ktime_to_real(e->timestamp), time_string);

	/* update hash table */
	get_fingerprint(&current_packet, fingerprint);
	if (current_packet.dst_port != 22)
		printf("%d handling %s\n", gettid(), fingerprint);

	/* look up hash table entry */
	pthread_rwlock_rdlock(&hash_table_lock);
	res = g_hash_table_lookup(packet_table, (gconstpointer) &fingerprint);
	pthread_rwlock_unlock(&hash_table_lock);

	if (res) {
		/* entry already exists: update count and timestamp */
		struct value *current_val = (struct value*) res;
		new_val.first = current_val->first;
		new_val.latest = ktime_to_real(e->timestamp);
		new_val.count = current_val->count + 1;
	} else {
		/* set up new entry */
		new_val.first = ktime_to_real(e->timestamp);
		new_val.latest = new_val.first;
		new_val.count = 1;
	}

	/* detect flag-based scans */
	if (is_xmas_scan(&e->tcph)) {
		printf("nmap Xmas scan detected from %s at %s (port %d)!\n",
				src_addr, time_string, current_packet.dst_port);

		pthread_rwlock_wrlock(&db_lock);
		log_alert(db_conn, fingerprint, XMAS_SCAN, &current_packet, &new_val);
		pthread_rwlock_unlock(&db_lock);
	}

	if (is_fin_scan(&e->tcph)) {
		printf("nmap FIN scan detected from %s at %s (port %d)!\n",
				src_addr, time_string, current_packet.dst_port);

		pthread_rwlock_wrlock(&db_lock);
		log_alert(db_conn, fingerprint, FIN_SCAN, &current_packet, &new_val);
		pthread_rwlock_unlock(&db_lock);
	}

	if (is_null_scan(&e->tcph)) {
		printf("nmap NULL scan detected from %s at %s (port %d)!\n",
				src_addr, time_string, current_packet.dst_port);

		pthread_rwlock_wrlock(&db_lock);
		log_alert(db_conn, fingerprint, NULL_SCAN, &current_packet, &new_val);
		pthread_rwlock_unlock(&db_lock);
	}

	/* insert/replace entry */
	pthread_rwlock_wrlock(&hash_table_lock);
	g_hash_table_replace(packet_table,
			g_strdup(fingerprint), g_memdup2((gconstpointer) &new_val, sizeof(struct value)));
	pthread_rwlock_wrlock(&hash_table_lock);

	if (current_packet.dst_port != 22) {
		char **port_fingerprints = gen_port_fingerprints(current_packet.src_ip);
		free_port_fingerprints(port_fingerprints);

		bool *ports_scanned = get_ports_scanned(current_packet.src_ip);
		printf("number of ports scanned: %d\n", count_ports_scanned(ports_scanned));
		free(ports_scanned);
	}

	/* debug: print corresponding hash table entry */
	pthread_rwlock_rdlock(&hash_table_lock);
	res = g_hash_table_lookup(packet_table, (gconstpointer) &fingerprint);
	pthread_rwlock_unlock(&hash_table_lock);

	struct value *current_val = (struct value*) res;
	if (current_packet.dst_port != 22) {
		printf("%s -> {%ld, %ld, %d}\n",
				fingerprint,
				current_val->first, current_val->latest, current_val->count);
	}

	/*
	if (current_packet.dst_port != 22) {
		update_db(db_conn, packet_table);
	}
	*/

	return 0;
}

void thread_rb_work()
{
	while (true) {
		err = ring_buffer__poll(rb, 100);

		/* EINTR = interrupted syscall */
		if (err == -EINTR) {
			err = 0;
			return;
		}

		if (err < 0) {
			pr_err("error polling ring buffer: %d\n", err);
			return;
		}
	}
}

int main(int argc, char *argv[])
{
	struct bpf_map *map = NULL;
	int prog_fd, map_fd;

	/* TODO get number of threads from argument/environment variable */
	int res;

	/* catch SIGINT (e.g. Ctrl+C, kill) */
	if (signal(SIGINT, cleanup) == SIG_ERR) {
		pr_err("error setting up SIGINT handler\n");
		return 1;
	}

	if (signal(SIGTERM, cleanup) == SIG_ERR) {
		pr_err("error setting up SIGTERM handler\n");
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
	db_conn = connect_db("root", "alerts");

	/* create hash table
	 *
	 * hash function = djb hash
	 * key equal function = string equality
	 */
	packet_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	printf("sizeof(key) = %d, sizeof(value) = %ld\n",
			MAX_FINGERPRINT, sizeof(struct value));

	/* extract common TCP ports from file */
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

	/* set up threads */
	num_threads = 2;
	threads = calloc(num_threads, sizeof(*threads));

	for (int i = 0; i < num_threads; i++) {
		res = pthread_create(&threads[i], NULL, (void *) thread_rb_work, NULL);
		if (res != 0) {
			pr_err("pthread create failed\n");
			cleanup();
		}
	}

	/* main thread also polls the ring buffer */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);

		/* EINTR = interrupted syscall */
		if (err == -EINTR) {
			err = 0;
			cleanup();
			break;
		}

		if (err < 0) {
			pr_err("error polling ring buffer: %d\n", err);
			cleanup();
			break;
		}
	}

	cleanup();
	return 0;

cleanup:
	/* redirect cleanup-related errors to /dev/null */
	freopen("/dev/null", "r", stderr);

	bpf_xdp_detach(ifindex, xdp_flags, NULL);
	ring_buffer__free(rb);
	free(common_ports);
	g_hash_table_destroy(packet_table);
	return err < 0 ? err : 0;
}
