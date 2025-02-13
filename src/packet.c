#include <stdint.h>
#include <stdio.h>

#include <errno.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
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
#include <cjson/cJSON.h>

#include "include/packet.h"
#include "include/bpf_load.h"
#include "include/pr.h"
#include "include/detect_scan.h"
#include "include/time_conv.h"
#include "include/parse_config.h"
#include "include/log.h"
#include "include/args.h"

#define XDP_RB_TIMEOUT 100  /* XDP ring buffer poll timeout (ms) */
#define LOG_FILENAME_LENGTH 24

uint32_t xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
int ifindex;

struct bpf_object *xdp_obj, *ip_uretprobe_obj,
                  *subnet_uretprobe_obj, *config_uretprobe_obj;

struct ring_buffer *xdp_rb = NULL;
struct user_ring_buffer *ip_rb = NULL;
struct user_ring_buffer *subnet_rb = NULL;
struct user_ring_buffer *config_rb = NULL;
int err;

GHashTable *packet_table;
struct db_task_queue task_queue_head;
pthread_mutex_t task_queue_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t task_queue_cond = PTHREAD_COND_INITIALIZER;

PGconn *db_conn;
pthread_t db_worker;

struct config current_config;
pthread_rwlock_t config_lock = PTHREAD_RWLOCK_INITIALIZER;
pthread_t inotify_worker;

int *common_ports = NULL; /* store top 1000 TCP ports */
const int NUM_COMMON_PORTS = 1000;
const int MAX_ADDR_LEN = 16;

bool exiting = false;
bool use_db_thread = false;

/* total time spent in handle_event() */
unsigned long total_handle_time = 0;
unsigned long total_packet_count = 0;

FILE *LOG = NULL;
int LOG_FD = -1;

void cleanup()
{
	if (exiting) {
		return;
	}

	exiting = true;

	bpf_xdp_detach(ifindex, xdp_flags, NULL);

	if (ip_rb) {
		user_ring_buffer__free(ip_rb);
	}

	if (config_rb) {
		user_ring_buffer__free(config_rb);
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
	close(LOG_FD);

	/* terminate database and inotify worker threads */
	/* TODO merge with init_cleanup() by checking if threads are running */
	pthread_kill(db_worker, SIGKILL);
	pthread_kill(inotify_worker, SIGKILL);

	/* exit(EXIT_SUCCESS); */
}

/* cleanup for initialisation */
void init_cleanup(int err)
{
	bpf_xdp_detach(ifindex, xdp_flags, NULL);

	if (xdp_rb) {
		ring_buffer__free(xdp_rb);
	}

	/* NOTE: common_ports currently not used
	if (common_ports) {
		free(common_ports);
	}
	*/

	if (packet_table) {
		g_hash_table_destroy(packet_table);
	}

	/* close log file if open */
	if (LOG)
		fclose(LOG);
	if (LOG_FD != -1)
		close(LOG_FD);

	exit(-err);
}

void cleanup_handler(int signum)
{
	cleanup();
	exit(EXIT_SUCCESS);
}

void print_stats(int signum)
{
	char buf[MAX_LOG_MSG];
	/*
	char prefix[MAX_PREFIX];
	char fmt[MAX_LOG_MSG];

	make_prefix(prefix, "stats: ");
	strncpy(fmt, prefix, MAX_LOG_MSG);
	strncat(fmt, "%ld packets per second\n", MAX_LOG_MSG - (strlen(prefix)+1));
	*/

	snprintf(buf, MAX_LOG_MSG, "stats: %ld packets per second\n",
			packet_rate(&total_packet_count, &total_handle_time));
	write(LOG_FD, buf, strlen(buf));
}

int skb_mode(char *arg)
{
	/* set SKB mode with bitwise OR */
	/* TODO fix */
	return strncmp(arg, "--skb-mode", strlen(arg)) == 0;
}

void gen_log_name(char *name)
{
	time_to_str(time(NULL), name,
			LOG_FILENAME_LENGTH, "log/%Y-%m-%d_%H-%M-%S");
}

void open_file(char *name, FILE **file)
{
	*file = fopen(name, "a");
	if (!(*file)) {
		perror("memory allocation failed");
		exit(errno);
	}
}

void get_fd(char *name, int *fd)
{
	*fd = open(name, O_RDWR | O_APPEND);
	if (*fd == -1) {
		perror("memory allocation failed");
		exit(errno);
	}
}

void init_log_file()
{
	/* TODO: replace with char[]? */
	char *filename = malloc(24 * sizeof(char));
	if (!filename) {
		perror("memory allocation failed");
		exit(errno);
	}
	gen_log_name(filename);

	open_file(filename, &LOG);
	get_fd(filename, &LOG_FD);

	free(filename);
}

void setup_signal_handlers()
{
	struct sigaction cleanup_action, stats_action;

	/* set up signal handlers
	 *
	 * SIGINT, SIGTERM: cleanup and exit
	 * USR1: print performance statistics (similar to the dd command)
	 */
	cleanup_action.sa_handler = cleanup_handler;
	sigemptyset(&cleanup_action.sa_mask);
	cleanup_action.sa_flags = 0;

	stats_action.sa_handler = print_stats;
	sigemptyset(&stats_action.sa_mask);
	stats_action.sa_flags = SA_RESTART;

	/* sigaction() returns 0 on success, -1 on error and sets errno to indicate
	 * the error */
	if (sigaction(SIGINT, &cleanup_action, NULL) == -1) {
		log_error("SIGINT handler: %s\n", strerror(errno));
		exit(errno);
	}

	if (sigaction(SIGTERM, &cleanup_action, NULL) == -1) {
		log_error("SIGTERM handler: %s\n", strerror(errno));
		exit(errno);
	}

	if (sigaction(SIGUSR1, &stats_action, NULL) == -1) {
		log_error("SIGUSR handler: %s\n", strerror(errno));
		exit(errno);
	}
}

void get_thread_env(bool *use_db_thread) {
	/* check if we're using the database worker thread */
	char *thread_env = getenv("DB_THREAD");

	if (thread_env) {
		/* strncmp() returns 0 if strings are equal */
		*use_db_thread = strncmp(getenv("DB_THREAD"), "true", 5) == 0;
	} else {
		*use_db_thread = true;
	}

#ifdef DEBUG
	log_debug("use database worker thread: %d\n", use_db_thread);
#endif
}

int get_bpf_map_fd(struct bpf_object *obj, char *name) {
	struct bpf_map *map;

	map = bpf_object__find_map_by_name(obj, name);
	if (!map) {
		log_error("cannot find map by name %s\n", name);
		init_cleanup(-1);
	}
	return bpf_map__fd(map);
}

void init_kernel_rb(struct ring_buffer **rb, int fd, void *callback)
{
	*rb = ring_buffer__new(fd, callback, NULL, NULL);
	if (!*rb) {
		err = -1;
		log_error("failed to create kernel ring buffer (fd %d)\n", fd);
		init_cleanup(err);
	}
}

void init_user_rb(struct user_ring_buffer **rb, int fd)
{
	*rb = user_ring_buffer__new(fd, NULL);
	if (!*rb) {
		err = -1;
		log_error("failed to create user ring buffer (fd %d)\n", fd);
		init_cleanup(err);
	}
}

void init_db_thread(void *function, struct db_thread_args *args)
{
		int res = pthread_create(&db_worker, NULL,
				function , args);
		if (res != 0) {
			log_error("%s\n", "db_worker pthread_create failed");
			cleanup();
			exit(res);
		}
}

void init_inotify_thread(void *function, struct inotify_thread_args *args)
{
	int res = pthread_create(&inotify_worker, NULL,
			function, &args);
	if (res != 0) {
		log_error("%s\n", "config_worker pthread_create failed");
		cleanup();
		exit(res);
	}
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

void ip_to_str(in_addr_t address, char buffer[]) {
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

/* submit IP list entry (black/whitelist) to BPF program with user ring buffer */
__attribute__((noinline)) int submit_ip_entry(__u32 src_ip, int type)
{
	int err = 0;
	struct ip_rb_event *e;

	e = user_ring_buffer__reserve(ip_rb, sizeof(*e));
	if (!e) {
		err = -errno;
		return err;
	}

	/* fill out ring buffer sample */
	e->src_ip = src_ip;
	e->type = type;

	/* submit ring buffer event */
	user_ring_buffer__submit(ip_rb, e);
	return err;
}

/* submit blacklist and whitelist to BPF program */
void submit_ip_list()
{
	pthread_rwlock_rdlock(&config_lock);
	if (current_config.blacklist_ip) {
		for (int i = 0; i < current_config.blacklist_ip->size; i++) {
			submit_ip_entry(current_config.blacklist_ip->entries[i], BLACKLIST);
		}
	}

	if (current_config.whitelist_ip) {
		for (int i = 0; i < current_config.whitelist_ip->size; i++) {
			submit_ip_entry(current_config.whitelist_ip->entries[i], WHITELIST);
		}
	}
	pthread_rwlock_unlock(&config_lock);
}

__attribute__((noinline)) int submit_subnet_entry(struct subnet *entry,
        int index, int type)
{
    int err = 0;
    struct subnet_rb_event *e;

    e = user_ring_buffer__reserve(subnet_rb, sizeof(*e));
    if (!e) {
        err = -errno;
        return err;
    }

    /* fill out ring buffer sample */
    e->mask = entry->mask;
    e->network_addr = entry->network_addr;
    e->index = index;
    e->type = type;

    user_ring_buffer__submit(subnet_rb, e);
    return err;
}

void submit_subnet_list()
{
    int index = 0;

    pthread_rwlock_rdlock(&config_lock);
    if (current_config.blacklist_subnet) {
        for (int i = 0; i < current_config.blacklist_subnet->size; i++) {
            submit_subnet_entry(&current_config.blacklist_subnet->entries[i],
                    index, BLACKLIST);
            index++;
        }
    }
    if (current_config.whitelist_subnet) {
        for (int i = 0; i < current_config.whitelist_subnet->size; i++) {
            submit_subnet_entry(&current_config.whitelist_subnet->entries[i],
                    index, WHITELIST);
            index++;
        }
    }
    pthread_rwlock_unlock(&config_lock);
}

__attribute__((noinline)) int submit_action_config()
{
	int err = 0;
	struct config_rb_event *e;

	e = user_ring_buffer__reserve(config_rb, sizeof(*e));
	if (!e) {
		err = -errno;
		return err;
	}

#ifdef DEBUG
	log_debug("%s\n", "submitting config");
#endif

	/* fill out ring buffer sample */
	pthread_rwlock_rdlock(&config_lock);
	e->block_src = current_config.block_src;
	e->redirect_ip = current_config.redirect_ip;
	pthread_rwlock_unlock(&config_lock);

	user_ring_buffer__submit(config_rb, e);

	return err;
}

/* called for each packet sent through the ring buffer */
int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct xdp_rb_event *e = data;
    char address[MAX_ADDR_LEN];
	int dst_port;

	struct key current_key;
	struct value new_val;
	gpointer res;

	bool is_alert = false; /* did this packet cause an alert? */
	bool flagged = false;  /* did this IP get flagged? */

	/* measure start time */
	struct timespec start_time, end_time, delta;
	/* TODO separate time measurement into function */
	clock_gettime(CLOCK_MONOTONIC, &start_time);

	/* extract data from IP and TCP headers */
	/* source IP address */
	current_key.src_ip = ntohl(src_addr(&e->ip_header));

	/* destination TCP port */
	dst_port = get_dst_port(&e->tcp_header);

	ip_to_str(current_key.src_ip, address);

	/* update hash table */
	/* look up hash table entry */
	res = g_hash_table_lookup(packet_table, (gconstpointer) &current_key.src_ip);

	/* TODO replace with function */
	if (res) {
		/* entry already exists: update count and timestamp */
		struct value *current_val = (struct value*) res;
		new_val.first = current_val->first;
		new_val.latest = time(NULL);
		new_val.total_packet_count = current_val->total_packet_count + 1;
		new_val.total_port_count = current_val->total_port_count;

		/* copy per-port counts */
		memcpy(new_val.ports, current_val->ports, NUM_PORTS * sizeof(unsigned long));

		/* increment port count if this is a new port */
		if (new_val.ports[dst_port] == 0) {
			new_val.total_port_count++;
		}

#ifdef DEBUG
		log_debug("total port count for %s = %d\n", address, new_val.total_port_count);
#endif

		/* increment packet count for current destination port */
		new_val.ports[dst_port]++;
	} else {
		/* set up new entry */
		new_val.first = time(NULL);
		new_val.latest = new_val.first;

		/* explicitly zero port count array */
		memset(new_val.ports, 0, NUM_PORTS * sizeof(unsigned long));
		/* set up total packete and port counts */
		new_val.total_packet_count = 1;
		new_val.total_port_count = 1;
		new_val.ports[dst_port] = 1;
	}


	/* detect flag-based scans */
	if (is_xmas_scan(&e->tcp_header)) {
		pthread_rwlock_rdlock(&config_lock);
		int packet_threshold = current_config.packet_threshold;
		pthread_rwlock_unlock(&config_lock);

		if (new_val.total_packet_count >= packet_threshold) {
			is_alert = true;

			log_alert("nmap Xmas scan detected from %s (port %d)!\n",
					address, dst_port);

			if (use_db_thread) {
				queue_work(&task_queue_head, &task_queue_lock, &task_queue_cond,
						 XMAS_SCAN, &current_key, &new_val, dst_port);
			} else {
				db_alert(db_conn, XMAS_SCAN,
						&current_key, &new_val, dst_port);
			}
		}
	}

	if (is_fin_scan(&e->tcp_header)) {
		pthread_rwlock_rdlock(&config_lock);
		int packet_threshold = current_config.packet_threshold;
		pthread_rwlock_unlock(&config_lock);

		if (new_val.total_packet_count >= packet_threshold) {
			is_alert = true;

			log_alert("nmap FIN scan detected from %s (port %d)!\n",
					address, dst_port);

			if (use_db_thread) {
				queue_work(&task_queue_head, &task_queue_lock, &task_queue_cond,
						 FIN_SCAN, &current_key, &new_val, dst_port);
			} else {
				db_alert(db_conn, FIN_SCAN, &current_key, &new_val, dst_port);
			}
		}

	}

	if (is_null_scan(&e->tcp_header)) {
		pthread_rwlock_rdlock(&config_lock);
		int packet_threshold = current_config.packet_threshold;
		pthread_rwlock_unlock(&config_lock);

		if (new_val.total_packet_count >= packet_threshold) {
			is_alert = true;

			log_alert("nmap NULL scan detected from %s (port %d)!\n",
					address, dst_port);

			if (use_db_thread) {
				queue_work(&task_queue_head, &task_queue_lock, &task_queue_cond,
						 NULL_SCAN, &current_key, &new_val, dst_port);
			} else {
				db_alert(db_conn, NULL_SCAN, &current_key, &new_val, dst_port);
			}
		}
	}

	/* NOTE avoids logging every time we send an SSH packet */
	/*
	char **port_fingerprints = ip_fingerprint(current_key.src_ip);
	free_ip_fingerprint(port_fingerprints);
	*/

	/* read port threshold from config */
	pthread_rwlock_rdlock(&config_lock);
	long port_threshold = current_config.port_threshold;
	pthread_rwlock_unlock(&config_lock);

	if (new_val.total_port_count >= port_threshold) {
		is_alert = true;
		log_alert("nmap (%d or more ports) detected from %s!\n",
				port_threshold, address);

		if (use_db_thread) {
			queue_work(&task_queue_head, &task_queue_lock, &task_queue_cond,
				PORT_SCAN, &current_key, &new_val, 0);
		} else {
			db_alert(db_conn, PORT_SCAN, &current_key, &new_val, 0);
		}
	}

	if (is_alert) {
		/* incrment alert count */
		new_val.alert_count++;

		pthread_rwlock_rdlock(&config_lock);
		int flag_threshold = current_config.flag_threshold;
		pthread_rwlock_unlock(&config_lock);

		/* check current number of alerts */
#ifdef DEBUG
		log_debug("alert count for %s: %d\n", address, new_val.alert_count);
#endif

		/* flag IP if config threshold reached */
		if (new_val.alert_count >= flag_threshold) {
			log_alert("flagging %s\n", address);
			flagged = true;
			submit_ip_entry(current_key.src_ip, BLACKLIST);

            if (use_db_thread) {
				queue_work(&task_queue_head, &task_queue_lock, &task_queue_cond,
					0, &current_key, &new_val, 0);
            } else {
                db_flagged(db_conn, &current_key, &new_val);
            }
		}
	}

	/* update hash table */
	if (flagged) {
        /* flagged: remove IP entry from hash table */
		g_hash_table_remove(packet_table, (gconstpointer) &current_key.src_ip);
	} else {
		/* insert/update entry */
		g_hash_table_replace(packet_table,
				g_memdup2((gconstpointer) &current_key.src_ip, sizeof(in_addr_t)),
				g_memdup2((gconstpointer) &new_val, sizeof(struct value)));
	}

	/* measure end time */
	clock_gettime(CLOCK_MONOTONIC, &end_time);
	delta = time_diff(&start_time, &end_time);
	total_handle_time += delta.tv_sec + delta.tv_nsec;
	/* update total packet count */
	total_packet_count++;

#ifdef DEBUG
	/* avoid printing out handle_event() time for every SSH packet! */
	if (dst_port != 22) {
		log_debug("time taken: %ld ns\n", delta.tv_nsec);
		log_debug("total handle_event time: %ld ns\n", total_handle_time);
		printf("total handle_event time: %ld ns, total packets: %ld\n", 
				total_handle_time, total_packet_count);
		printf("packet rate: %ld\n", packet_rate(&total_packet_count, &total_handle_time));
	}
#endif

	return 0;
}

void handle_inotify_events(int fd, const char *target_filename,
		struct config *current_config, pthread_rwlock_t *lock)
{
	/* buffer used for reading from inotify fd should have same alignment as
	 * struct inotify_event
	 *
	 * (see inotify(7) for more details)
	 */
	char buf[MAX_EVENT]
		__attribute__((aligned(__alignof__(struct inotify_event))));
	const struct inotify_event *event;
	size_t len;

	/* loop while events can be read from fd */
	while (1) {
		/* read events */
		len = read(fd, buf, sizeof(buf));
		if (len == -1 && errno != EAGAIN) {
			/* read failed */
			log_error("read inotify fd failed: %s\n", strerror(errno));
			break;
		}

		if (len <= 0) {
			/* read() returns -1 && errno == EAGAIN => no events to read */
			break;
		}

		/* loop over events
		 * step forward by inotify_event size + event name each time */
		for (char *ptr = buf; ptr < buf + len;
				ptr += sizeof(struct inotify_event) + event->len) {
			event = (const struct inotify_event *) ptr;

			/* we only care about the config file */
			if (event->len && strcmp(event->name, target_filename) == 0) {
				cJSON *config_json = json_config(config_path);
				if (!config_json) {
					log_error("%s\n", "invalid JSON");
				} else {
					apply_config(config_json, current_config, lock);

					/* submit config: action, and black/whitelisted IPs */
					submit_action_config();
					submit_ip_list();
                    submit_subnet_list();

					cJSON_Delete(config_json);
				}
			}
		}

	}
}

void inotify_thread_work(void *args)
{
	struct inotify_thread_args *ctx = args;

	int poll_num, inotify_fd, wd;
	nfds_t nfds;
	struct pollfd poll_fd;

	struct config *current_config = ctx->current_config;
	pthread_rwlock_t *lock = ctx->lock;

	/* TODO split provided config path on slash to get directory and filename */
	const char *CONFIG_FILENAME = "config.json"; /* 12 bytes */
	const char *CONFIG_DIR = "config";           /* 7 bytes */

	/* set up config path */
	snprintf(config_path, CONFIG_PATH_LEN, "%s/%s", CONFIG_DIR, CONFIG_FILENAME);
#ifdef DEBUG
	log_debug("config path: %s\n", config_path);
#endif

	/* create inotify file descriptor */
	inotify_fd = inotify_init();
	if (inotify_fd == -1) {
		log_error("inotify_init: %s\n", strerror(errno));
	}

	/* watch for changes to files in the config directory
	 * wd = watch file descriptor */
	wd = inotify_add_watch(inotify_fd, CONFIG_DIR, IN_CLOSE_WRITE);
	if (wd == -1) {
		log_error("inotify: cannot watch '%s': %s\n",
				CONFIG_DIR, strerror(errno));
		return;
	}

	/* set up polling */
	nfds = 1;
	poll_fd.fd = inotify_fd;
	poll_fd.events = POLLIN;

	/* NOTE: main thread has already applied default and initial config at this
	 * point */

	/* wait for events and handle them when they occur */
	while (1) {
		/* poll_num = number of elements in our poll_fd with non zero revents
		 * (real events)
		 *
		 * third argument to poll() = timeout
		 *     -> -1 means block until an event occurs */
		poll_num = poll(&poll_fd, nfds, -1);
		if (poll_num == -1) {
			switch (errno) {
				case EINTR:
					continue;
					break;
				default:
					log_error("inotify poll: %s\n", strerror(errno));
					break;
			}
		}

		/*
		 * events = types of events poller cares about
		 * revents = types of events that actually happened
		 */
		if (poll_num > 0) {
			if (poll_fd.revents & POLLIN) {
				/* inotify events available */
				handle_inotify_events(inotify_fd, CONFIG_FILENAME,
						current_config, lock);
			}
		}
	}
}

int main(int argc, char *argv[])
{
	struct args init_args;

    /* map file descriptors */
	int ip_list_fd, subnet_list_fd, config_hash_fd;

    /* ring buffers */
    int xdp_rb_fd, ip_rb_fd, subnet_rb_fd, config_rb_fd;

	cJSON *config_json;

	/* arguments to pass to database and inotify worker threads */
	struct db_thread_args db_worker_args;
	struct inotify_thread_args inotify_worker_args;

	struct uretprobe_opts ip_uretprobe_args,
						  subnet_uretprobe_args, config_uretprobe_args;

	/* TODO replace hardcoded filenames (take arguments using getopt) */
	/* NOTE testing */
	parse_args(argc, argv, &init_args);

	if (!init_args.interface) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (init_args.skb_mode) {
		xdp_flags |= XDP_FLAGS_SKB_MODE;
	}

	ifindex = if_nametoindex(init_args.interface);
	if (ifindex == 0) {
		/* TODO better error message */
		perror("error setting up interface");
		exit(errno);
	}

	/* initialise and open log file */
	init_log_file();

	/* set up config file */
	set_default_config(&current_config, &config_lock);
	config_json = json_config(init_args.config);
	if (!config_json) {
		log_debug("no config file found at %s\n", init_args.config);
	} else {
		/* apply initial config */
		apply_config(config_json, &current_config, &config_lock);
	}

	setup_signal_handlers();

	get_thread_env(&use_db_thread);

    /* load and attach XDP program */
    err = init_xdp_prog(&xdp_obj, init_args.bpf_obj_file, "process_packet",
            ifindex, xdp_flags);
	if (err < 0)
		goto fail;

	/* get IP hash map file descriptor so it can be shared with the
	 * corresponding uretprobe */
	ip_list_fd = get_bpf_map_fd(xdp_obj, "ip_list");
	subnet_list_fd = get_bpf_map_fd(xdp_obj, "subnet_list");

    /* load and attach IP list uretprobe */
	ip_uretprobe_args.uretprobe_obj = &ip_uretprobe_obj;
	ip_uretprobe_args.filename = init_args.bpf_obj_file;
	ip_uretprobe_args.program_name = "read_ip_rb";
	ip_uretprobe_args.uprobe_func = "submit_ip_entry";
	ip_uretprobe_args.bpf_map_fd = ip_list_fd;
	ip_uretprobe_args.map_name = "ip_list";
	if (init_uretprobe(&ip_uretprobe_args) <= 0) {
		log_error("failed to load uretprobe program from file: %s\n",
				init_args.bpf_obj_file);
		err = -1;
		init_cleanup(err);
	}

    /* load and attach subnet list uretprobe */
	subnet_uretprobe_args.uretprobe_obj = &subnet_uretprobe_obj;
	subnet_uretprobe_args.filename = init_args.bpf_obj_file;
	subnet_uretprobe_args.program_name = "read_subnet_rb";
	subnet_uretprobe_args.uprobe_func = "submit_subnet_entry";
	subnet_uretprobe_args.bpf_map_fd = subnet_list_fd;
	subnet_uretprobe_args.map_name = "subnet_list";
	if (init_uretprobe(&subnet_uretprobe_args) <= 0) {
		log_error("failed to load uretprobe program from file: %s\n",
				init_args.bpf_obj_file);
		err = -1;
		init_cleanup(err);
	}

	/* get config hash map file descriptor so it can be shared with the
	 * corresponding uretprobe */
	config_hash_fd = get_bpf_map_fd(xdp_obj, "config");

	/* load and attach config uretprobe */
	config_uretprobe_args.uretprobe_obj = &config_uretprobe_obj;
	config_uretprobe_args.filename = init_args.bpf_obj_file;
	config_uretprobe_args.program_name = "read_config_rb";
	config_uretprobe_args.uprobe_func = "submit_action_config";
	config_uretprobe_args.bpf_map_fd = config_hash_fd;
	config_uretprobe_args.map_name = "config";
	if (init_uretprobe(&config_uretprobe_args) <= 0) {
		log_error("failed to load uretprobe program from file: %s\n",
				init_args.bpf_obj_file);
		err = -1;
		init_cleanup(err);
	}

	/* set up database */
	db_conn = connect_db("root", "alerts");
	if (!db_conn) {
		err = -1;
		init_cleanup(err);
	}

	/* create hash table
	 *
	 * hash function = djb hash
	 * key equal function = string equality
	 */
	packet_table = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, g_free);

	/* initialise database task queue */
	TAILQ_INIT(&task_queue_head);

	/* extract common TCP ports from file 
	 * NOTE currently unused */
	/* common_ports = get_port_list("top-1000-tcp.txt", NUM_COMMON_PORTS); */

	/* find kernel ring buffer */
	xdp_rb_fd = get_bpf_map_fd(xdp_obj, "xdp_rb");

	/* set up kernel ring buffer */
	init_kernel_rb(&xdp_rb, xdp_rb_fd, handle_event);

	/* set up IP list user ring buffer */
	ip_rb_fd = get_bpf_map_fd(ip_uretprobe_obj, "ip_rb");
	init_user_rb(&ip_rb, ip_rb_fd);

    /* set up subnet user ring buffer */
	subnet_rb_fd = get_bpf_map_fd(subnet_uretprobe_obj, "subnet_rb");
	init_user_rb(&subnet_rb, subnet_rb_fd);

	/* set up config user ring buffer */
	config_rb_fd = get_bpf_map_fd(config_uretprobe_obj,"config_rb");
	init_user_rb(&config_rb, config_rb_fd);

	/* submit initial config to BPF program */
	submit_action_config(); /* block/redirect blacklisted IPs */
	submit_ip_list(); /* IP blacklist + whitelist */
    submit_subnet_list(); /* subnet blacklist + whitelist */

	/* create database worker thread
	 *
	 * (pass database connection and task queue information as args to work
	 * function) */
	if (use_db_thread) {
		db_worker_args.db_conn = db_conn;
		db_worker_args.head = &task_queue_head;
		db_worker_args.task_queue_lock = &task_queue_lock;
		db_worker_args.task_queue_cond = &task_queue_cond;

		init_db_thread((void *) db_thread_work, &db_worker_args);
	}

	/* create config file worker thread
	 *
	 * (pass config structure as argument to work function) */
	inotify_worker_args.current_config = &current_config;
	inotify_worker_args.lock = &config_lock;
	init_inotify_thread((void *) inotify_thread_work, &inotify_worker_args);

	/* poll ring buffer */
	while (!exiting) {
		err = ring_buffer__poll(xdp_rb, XDP_RB_TIMEOUT);

		/* EINTR = interrupted syscall */
		if (err == -EINTR) {
			continue;
		}

		if (err < 0) {
			log_error("ring buffer polling failed: %d\n", err);
			break;
		}
	}

	cleanup();
	return 0;

fail:
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
			log_error("XDP attach on %s failed %d: %s\n",
				argv[1], err, strerror(-err));
			break;
	}

	return -err;
}
