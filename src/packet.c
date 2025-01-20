#include <cjson/cJSON.h>
#include <stdio.h>

#include <errno.h>
#include <string.h>
#include <time.h>

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

#include "include/packet.h"
#include "include/pr.h"
#include "include/detect_scan.h"
#include "include/time_conv.h"
#include "include/parse_config.h"
#include "include/log.h"

struct bpf_object *xdp_obj, *uretprobe_obj;
uint32_t xdp_flags;
int ifindex;

struct ring_buffer *xdp_rb = NULL;
struct user_ring_buffer *flagged_rb = NULL;
int err;

GHashTable *packet_table;
struct db_task_queue task_queue_head;
pthread_mutex_t task_queue_lock = PTHREAD_MUTEX_INITIALIZER;

PGconn *db_conn;
pthread_t db_worker;
pthread_mutex_t db_lock = PTHREAD_MUTEX_INITIALIZER;

struct config current_config;
pthread_rwlock_t config_lock = PTHREAD_RWLOCK_INITIALIZER;
pthread_t inotify_worker;

int *common_ports = NULL; /* store top 1000 TCP ports */
const int NUM_COMMON_PORTS = 1000;
const int MAX_ADDR_LEN = 16;

bool exiting = false;
bool use_db_thread = false;

/* #ifdef DEBUG */
long total_handle_time = 0.0;
/* #endif */

FILE *LOG;

void cleanup()
{
	if (exiting) {
		return;
	}

	exiting = true;

	bpf_xdp_detach(ifindex, xdp_flags, NULL);

	if (flagged_rb) {
		user_ring_buffer__free(flagged_rb);
	}

	if (xdp_rb) {
		ring_buffer__free(xdp_rb);
	}

	if (common_ports) {
		free(common_ports);
	}

	if (packet_table) {
		g_hash_table_destroy(packet_table);
	}

	fclose(LOG);

	/* terminate database and inotify worker threads */
	pthread_kill(db_worker, SIGKILL);
	pthread_kill(inotify_worker, SIGKILL);

	exit(EXIT_SUCCESS);
}

/* TODO switch signal() to sigaction()
void handle_signal(int signum) {
	if (signum == SIGINT || signum == SIGTERM) {
		signal(signum, cleanup);
	}
	return;
}
*/


int load_bpf_xdp(const char *filename)

{
	int prog_fd = -1;
	int err;
	struct bpf_program *prog;

	xdp_obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(xdp_obj)) {
		log_error("open object file failed: %s\n", strerror(errno));
		return -1;
	}

	prog = bpf_object__find_program_by_name(xdp_obj, "process_packet");
	if (prog == NULL) {
		log_error("find program in object failed: %s\n", strerror(errno));
		return -1;
	}

	/* set to XDP */
	if (bpf_program__set_type(prog, BPF_PROG_TYPE_XDP) < 0) {
		log_error("set bpf type to xdp failed: %s\n", strerror(errno));
		return -1;
	}

	err = bpf_object__load(xdp_obj);
	if (err) {
		log_error("load bpf object failed: %s\n", strerror(errno));
		return -1;
	}

	prog_fd = bpf_program__fd(prog);
	if (!prog_fd) {
		log_error("failed to load bpf object file (%s)- %d: %s\n",
				filename, errno, strerror(errno));
		return -1;
	}

	return prog_fd;
}

int load_and_attach_bpf_uretprobe(const char *filename, int flagged_ips_fd)
{
	int prog_fd = -1;
	int err;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);
	struct bpf_program *prog;
	struct bpf_map *flagged_ips;

	uretprobe_obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(uretprobe_obj)) {
		log_error("open object file failed: %s\n", strerror(errno));
		return -1;
	}

	prog = bpf_object__find_program_by_name(uretprobe_obj, "read_flagged_rb");
	if (prog == NULL) {
		log_error(msg, "find program in object failed: %s\n", strerror(errno));
		return -1;
	}

	flagged_ips = bpf_object__find_map_by_name(uretprobe_obj, "flagged_ips");
	err = bpf_map__reuse_fd(flagged_ips, flagged_ips_fd);
	if (err) {
		log_error("failed to reuse map fd: %s\n", strerror(errno));
		return -1;
	}

	err = bpf_object__load(uretprobe_obj);
	if (err) {
		log_error("load bpf object failed: %s\n", strerror(errno));
		return -1;
	}

	prog_fd = bpf_program__fd(prog);
	if (!prog_fd) {
		log_error("failed to load bpf object file(%s) (%d): %s\n",
				filename, err, strerror(-err));
	}

	/* name of function to attach to */
	uprobe_opts.func_name = "submit_flagged_ip";
	/* uretprobe = attach to function exit (we want to read the ring buffer
	 * after we're done submitting) */
	uprobe_opts.retprobe = true;

	/* Attach BPF uprobe
	 * prog: BPF program to attach
	 * pid: 0 for self (own process)
	 * binary_path: path to binary containing function symbol
	 * func_offset: offset within binary (set to 0 since we provided function
	 * 				name in uprobe_otps)
	 * opts: options
	 */
	if (!bpf_program__attach_uprobe_opts(prog, 0, 
				"/proc/self/exe", 0, &uprobe_opts)) {
		log_error("uprobe attach failed: %s\n", strerror(errno));
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
		if (!port_list) {
			pr_err("memory allocation failed: %s\n", strerror(errno));
			cleanup();
			exit(1);
		}


		while (token) {
			port_list[index++] = atoi(token);
			token = strtok(NULL, delim);
		}
		free(buffer);
	} else {
		log_error("failed to open file %s\n", filename);
		exit(1);
	}

	/* close file */
	fclose(fptr);
	return port_list;
}

/* get list of ports a given IP (and flag combination) has sent packets to */
void ports_scanned(long src_ip, bool *ports_scanned)
{
	char **fingerprint = ip_fingerprint(src_ip);
	gboolean res;

	for (int i = 0; i < NUM_PORTS; i++) {
		res = g_hash_table_contains(packet_table, (gconstpointer) fingerprint[i]);
		ports_scanned[i] = res;
	}

	free_ip_fingerprint(fingerprint);
}

/* get information about packets a given IP has sent
 *
 * struct port_info contains information about ports the source IP has sent
 * packets to and the total number of packets it has sent
 */
void port_info(long src_ip, struct port_info *info)
{
	char **fingerprint = ip_fingerprint(src_ip);
	struct value *res;

	info->total_packet_count = 0;

	for (int i = 0; i < NUM_PORTS; i++) {
		res = g_hash_table_lookup(packet_table, (gconstpointer) fingerprint[i]);

		if (res != NULL) {
			info->ports_scanned[i] = true;
			info->total_packet_count++;
		} else {
			info->ports_scanned[i] = false;
		}
	}

	free_ip_fingerprint(fingerprint);
}

/* submit flagged IP to BPF program with user ring buffer */
__attribute__((noinline)) int submit_flagged_ip(long src_ip)
{
	int err = 0;
	struct flagged_rb_event *e;

	e = user_ring_buffer__reserve(flagged_rb, sizeof(*e));
	if (!e) {
		err = -errno;
		return err;
	}

	/* fill out ring buffer sample */
	e->src_ip = src_ip;

	/* submit ring buffer event */
	user_ring_buffer__submit(flagged_rb, e);
	return err;
}


/* called for each packet sent through the ring buffer */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct xdp_rb_event *e = data;
	time_t timestamp;
    char address[MAX_ADDR_LEN], time_string[32];
	bool ports[NUM_PORTS];
	struct port_info info;

	struct key current_packet;
	struct value new_val;
	char fingerprint[MAX_FINGERPRINT];
	gpointer res;

	bool is_alert = false; /* did this packet cause an alert? */
	int alert_count;       /* number of alerts from current source IP */


/* #ifdef DEBUG */
	/* measure start time */
	struct timespec start_time, end_time, delta;
	clock_gettime(CLOCK_MONOTONIC, &start_time);
/* #endif */

	/* packet timestamp */
	timestamp = time(NULL);

	/* extract data from IP and TCP headers */
	/* source IP address */
	current_packet.src_ip = src_addr(&e->ip_header);

	/* destination TCP port */
	current_packet.dst_port = get_dst_port(&e->tcp_header);

	ip_to_str(current_packet.src_ip, address);
	time_to_str(timestamp, time_string, 32, "%H:%M:%S");
	ports_scanned(current_packet.src_ip, ports);
	port_info(current_packet.src_ip, &info);

	/* update hash table */
	get_fingerprint(&current_packet, fingerprint);

	/* look up hash table entry */
	res = g_hash_table_lookup(packet_table, (gconstpointer) &fingerprint);

	if (res) {
		/* entry already exists: update count and timestamp */
		struct value *current_val = (struct value*) res;
		new_val.first = current_val->first;
		new_val.latest = timestamp;
		new_val.count = current_val->count + 1;
	} else {
		/* set up new entry */
		new_val.first = timestamp;
		new_val.latest = new_val.first;
		new_val.count = 1;
	}

	/* insert/replace hash table entry */
	g_hash_table_replace(packet_table,
			g_strdup(fingerprint), g_memdup2((gconstpointer) &new_val, sizeof(struct value)));

	/* detect flag-based scans */
	if (is_xmas_scan(&e->tcp_header)) {
		pthread_rwlock_rdlock(&config_lock);
		int packet_threshold = current_config.packet_threshold;
		pthread_rwlock_unlock(&config_lock);

		if (new_val.count >= packet_threshold) {
			is_alert = true;

			log_alert("nmap Xmas scan detected from %s (port %d)!\n",
					address, current_packet.dst_port);

			if (use_db_thread) {
				queue_work(&task_queue_head, &task_queue_lock,
						 fingerprint, XMAS_SCAN, &current_packet, &new_val, NULL);
			} else {
				db_alert(db_conn, &db_lock, fingerprint, XMAS_SCAN,
						&current_packet, &new_val, NULL);
			}
		}
	}

	if (is_fin_scan(&e->tcp_header)) {
		pthread_rwlock_rdlock(&config_lock);
		int packet_threshold = current_config.packet_threshold;
		pthread_rwlock_unlock(&config_lock);

		if (new_val.count >= packet_threshold) {
			is_alert = true;

			log_alert("nmap FIN scan detected from %s (port %d)!\n",
					address, current_packet.dst_port);

			if (use_db_thread) {
				queue_work(&task_queue_head, &task_queue_lock,
						 fingerprint, FIN_SCAN, &current_packet, &new_val, NULL);
			} else {
				db_alert(db_conn, &db_lock, fingerprint, FIN_SCAN,
						&current_packet, &new_val, NULL);
			}
		}

	}

	if (is_null_scan(&e->tcp_header)) {
		pthread_rwlock_rdlock(&config_lock);
		int packet_threshold = current_config.packet_threshold;
		pthread_rwlock_unlock(&config_lock);

		if (new_val.count >= packet_threshold) {
			is_alert = true;

			log_alert("nmap NULL scan detected from %s (port %d)!\n",
					address, current_packet.dst_port);

			if (use_db_thread) {
				queue_work(&task_queue_head, &task_queue_lock,
						 fingerprint, NULL_SCAN, &current_packet, &new_val, NULL);
			} else {
				db_alert(db_conn, &db_lock, fingerprint, NULL_SCAN,
						&current_packet, &new_val, NULL);
			}
		}
	}

	/* NOTE avoids logging every time we send an SSH packet */
	char **port_fingerprints = ip_fingerprint(current_packet.src_ip);
	free_ip_fingerprint(port_fingerprints);

	pthread_rwlock_rdlock(&config_lock);
	long port_threshold = current_config.port_threshold;
	pthread_rwlock_unlock(&config_lock);

	if (is_basic_scan(ports, port_threshold)) {
		is_alert = true;
		log_alert("nmap (%d or more ports) detected from %s!\n",
				port_threshold, address);

		if (use_db_thread) {
			queue_work(&task_queue_head, &task_queue_lock, NULL, BASIC_SCAN,
					&current_packet, &new_val, &info);
		} else {
			db_alert(db_conn, &db_lock,
					NULL, BASIC_SCAN, &current_packet, &new_val, &info);
		}
	}

	if (is_alert) {
		pthread_rwlock_rdlock(&config_lock);
		int flag_threshold = current_config.flag_threshold;
		pthread_rwlock_unlock(&config_lock);

		/* check current number of alerts */
		alert_count = get_alert_count(db_conn, &db_lock, address);
#ifdef DEBUG
		log_debug("alert count: %d\n", alert_count);
#endif

		/* flag IP if config threshold reached */
		if (alert_count >= flag_threshold) {
			log_alert("flagging %s\n", address);
			submit_flagged_ip(current_packet.src_ip);
		}
	}

/* #ifdef DEBUG */
	/* measure end time */
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	delta = diff(&start_time, &end_time);
	total_handle_time += delta.tv_sec + delta.tv_nsec;

	if (current_packet.dst_port != 22) {
#ifdef DEBUG
		log_debug("time taken: %ld ns\n", delta.tv_nsec);
#endif
		log_debug("total handle_event time: %ld ns\n", total_handle_time);
	}

/* #endif */

/*
#ifdef DEBUG
	// print corresponding hash table entry
	res = g_hash_table_lookup(packet_table, (gconstpointer) &fingerprint);

	struct value *current_val = (struct value*) res;

	// don't print SSH-related entries
	if (current_packet.dst_port != 22) {
		log_debug("%s -> {%ld, %ld, %d}\n",
				fingerprint,
				current_val->first, current_val->latest, current_val->count);
	}
#endif
*/

	return 0;
}

int main(int argc, char *argv[])
{
	struct bpf_map *map = NULL;
	int xdp_prog_fd, uretprobe_prog_fd;
	int flagged_ips_fd, xdp_rb_fd, flagged_rb_fd;
	int res = 0;

	char *thread_env;

	struct db_thread_args db_worker_args;

	const char *BPF_FILENAME = "src/packet.bpf.o";
	const char *CONFIG_PATH = "config/config.json";

	char *log_filename = malloc(24 * sizeof(char));
	if (!log_filename) {
		pr_err("memory allocation failed: %s\n:", strerror(errno));
		return 1;
	}

	time_to_str(time(NULL), log_filename, 24, "log/%Y-%m-%d_%H-%M-%S");

	LOG = fopen(log_filename, "a");
	free(log_filename);

	if (!LOG) {
		pr_err("%s\n", strerror(errno));
		return -1;
	}

	/* apply default config */
	set_default_config(&current_config, &config_lock);

	/* get config options */
	cJSON *config_json = json_config(CONFIG_PATH);
	if (!config_json) {
		log_debug("no config file found at %s\n", CONFIG_PATH);
	} else {
		/* apply initial config */
		apply_config(config_json, &current_config, &config_lock);
	}

	/* catch SIGINT (e.g. Ctrl+C, kill) */
	if (signal(SIGINT, cleanup) == SIG_ERR) {
		log_error("%s\n", "failed to set up SIGINT handler");
		return 1;
	}

	if (signal(SIGTERM, cleanup) == SIG_ERR) {
		log_error("%s\n", "failed to set up SIGTERM handler");
		return 1;
	}

	/* TODO ???
	if (signal(SIGKILL, cleanup) == SIG_ERR) {
		log_error("%s\n", "failed to set up SIGKILL handler");
		return 1;
	}
	*/

	/* check we have the second argument */
	if (argc < 2) {
		log_error("usage: %s <interface name> [--skb-mode]\n", argv[0]);
		return -1;
	}

	/* check if we're using the database worker thread */
	thread_env = getenv("DB_THREAD");

	if (thread_env) {
		/* strncmp() returns 0 if strings are equal */
		use_db_thread = strncmp(getenv("DB_THREAD"), "true", 5) == 0;
	} else {
		use_db_thread = true;
	}

#ifdef DEBUG
	log_debug("use database worker thread: %d\n", use_db_thread);
#endif

	xdp_prog_fd = load_bpf_xdp(BPF_FILENAME);
	if (xdp_prog_fd <= 0) {
		log_error("failed to load XDP program from file: %s\n", BPF_FILENAME);
		return -1;
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

	err = bpf_xdp_attach(ifindex, xdp_prog_fd, xdp_flags, NULL);
	if (err < 0) {
		log_error("XDP attach on %s failed %d: %s\n",
				argv[1], -err, strerror(-err));
		switch (-err) {
			case EBUSY:
			case EEXIST:
				log_error("XDP already loaded on device %s\n", argv[1]);
				break;
			case ENOMEM:
			case EOPNOTSUPP:
				log_error("native XDP not supported on device %s, try --skb-mode\n",
						argv[1]);
				break;
			default:
				break;
		}
		goto cleanup;
	}

	map = bpf_object__find_map_by_name(xdp_obj, "flagged_ips");
	if (!map) {
		log_error("cannot find map by name %s\n", "flagged_ips");
		err = -1;
		goto cleanup;
	}
	flagged_ips_fd = bpf_map__fd(map);

	uretprobe_prog_fd = load_and_attach_bpf_uretprobe(BPF_FILENAME, flagged_ips_fd);
	if (uretprobe_prog_fd <= 0) {
		log_error("failed to load uretprobe program from file: %s\n", BPF_FILENAME);
		err = -1;
		goto cleanup;
	}

	/* set up database */
	db_conn = connect_db("root", "alerts");

	/* create hash table
	 *
	 * hash function = djb hash
	 * key equal function = string equality
	 */
	packet_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	TAILQ_INIT(&task_queue_head);

	/* extract common TCP ports from file */
	common_ports = get_port_list("top-1000-tcp.txt", NUM_COMMON_PORTS);

	/* find kernel ring buffer */
	map = bpf_object__find_map_by_name(xdp_obj, "xdp_rb");
	if (!map) {
		log_error("cannot find map by name: %s\n", "xdp_rb");
		goto cleanup;
	}
	xdp_rb_fd = bpf_map__fd(map);

	/* set up kernel ring buffer */
	xdp_rb = ring_buffer__new(xdp_rb_fd, handle_event, NULL, NULL);
	if (!xdp_rb) {
		err = -1;
		log_error("%s\n", "failed to create kernel ring buffer");
		goto cleanup;
	}

	/* find user ring buffer */
	map = bpf_object__find_map_by_name(uretprobe_obj, "flagged_rb");
	if (!map) {
		log_error("cannot find map by name: %s\n", "flagged_rb");
		goto cleanup;
	}
	flagged_rb_fd = bpf_map__fd(map);

	/* set up user ring buffer */
	flagged_rb = user_ring_buffer__new(flagged_rb_fd, NULL);
	if (!flagged_rb) {
		err = -1;
		log_error("%s\n", "failed to create user ring buffer");
		goto cleanup;
	}

	/* create database worker thread
	 *
	 * (pass database connection and task queue information as args to work
	 * function) */
	if (use_db_thread) {
		db_worker_args.db_conn = db_conn;
		db_worker_args.db_lock = &db_lock;
		db_worker_args.head = &task_queue_head;
		db_worker_args.task_queue_lock = &task_queue_lock;
		res = pthread_create(&db_worker, NULL,
				(void *) db_thread_work, &db_worker_args);
		if (res != 0) {
			log_error("%s\n", "db_worker pthread_create failed");
			cleanup();
			return 1;
		}
	}

	/* create config file worker thread
	 *
	 * (pass config structure as argument to work function) */
	struct inotify_thread_args inotify_worker_args;
	inotify_worker_args.current_config = &current_config;
	inotify_worker_args.lock = &config_lock;

	res = pthread_create(&inotify_worker, NULL,
			(void *) inotify_thread_work, &inotify_worker_args);
	if (res != 0) {
		log_error("%s\n", "config_worker pthread_create failed");
		cleanup();
		return 1;
	}

	/* TODO config file ring buffer */

	/* poll ring buffer */
	while (!exiting) {
		err = ring_buffer__poll(xdp_rb, 100);

		/* EINTR = interrupted syscall */
		if (err == -EINTR) {
			err = 0;
			cleanup();
			break;
		}

		if (err < 0) {
			log_error("ring buffer polling failed: %d\n", err);
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

	if (xdp_rb) {
		ring_buffer__free(xdp_rb);
	}

	if (common_ports) {
		free(common_ports);
	}

	if (packet_table) {
		g_hash_table_destroy(packet_table);
	}

	return err < 0 ? err : 0;
}
