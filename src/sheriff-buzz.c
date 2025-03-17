#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <libgen.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if_link.h>

#include <bpf/libbpf.h>

#include <glib.h>
#include <postgresql/libpq-fe.h>
#include <cjson/cJSON.h>

#include "include/log.h"
#include "include/bpf_common.h"
#include "include/bpf_load.h"
#include "include/detect_scan.h"
#include "include/time_conv.h"
#include "include/parse_config.h"
#include "include/packet_data.h"
#include "include/parse_headers.h"
#include "include/args.h"

#define XDP_RB_TIMEOUT 100  /* XDP ring buffer poll timeout (ms) */
#define LOG_FILENAME_LENGTH 24

uint32_t xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
int ifindex;

struct bpf_object *xdp_obj, *ip_uretprobe_obj, *subnet_uretprobe_obj, 
				  *port_uretprobe_obj, *config_uretprobe_obj;


struct uretprobe_opts ip_uretprobe_args = {
	.program_name = "read_ip_rb",
	.uprobe_func = "submit_ip_entry",
	.map_name = "ip_list"
};


struct uretprobe_opts subnet_uretprobe_args = {
	.program_name = "read_subnet_rb",
	.uprobe_func = "submit_subnet_entry",
	.map_name = "subnet_list"
};

struct uretprobe_opts port_uretprobe_args = {
	.program_name = "read_port_rb",
	.uprobe_func = "submit_port_entry",
	.map_name = "port_list"
};

struct uretprobe_opts config_uretprobe_args =  {
	.program_name = "read_config_rb",
	.uprobe_func = "submit_config",
	.map_name = "config"
};

struct ring_buffer *xdp_rb = NULL;
struct user_ring_buffer *ip_rb = NULL;
struct user_ring_buffer *subnet_rb = NULL;
struct user_ring_buffer *port_rb = NULL;
struct user_ring_buffer *config_rb = NULL;
int err;

GHashTable *packet_table;
struct db_task_queue task_queue_head;
pthread_mutex_t task_queue_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t task_queue_cond = PTHREAD_COND_INITIALIZER;

PGconn *db_conn;
pthread_t db_worker;

char *config_path;
struct config current_config;
pthread_rwlock_t config_lock = PTHREAD_RWLOCK_INITIALIZER;
pthread_t inotify_worker;

int *common_ports = NULL; /* store top 1000 TCP ports */
const int NUM_COMMON_PORTS = 1000;
const int MAX_ADDR_LEN = 16;

struct alert_type types;

bool exiting = false;
bool use_db_thread = false;

/* total time spent in handle_event() */
unsigned long total_handle_time = 0;
unsigned long total_packet_count = 0;
unsigned long total_blocked_ips = 0;

FILE *LOG = NULL;
int LOG_FD = -1;

void cleanup()
{
	/* don't call cleanup() more than once by setting exiting to true */
	if (exiting) {
		return;
	}
	exiting = true;

	/* detach XDP program */
	bpf_xdp_detach(ifindex, xdp_flags, NULL);

	/* free ring buffers */
	if (ip_rb) {
		user_ring_buffer__free(ip_rb);
	}

	if (subnet_rb) {
		user_ring_buffer__free(subnet_rb);
	}

	if (port_rb) {
		user_ring_buffer__free(port_rb);
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
		port_table_cleanup(packet_table);
		g_hash_table_destroy(packet_table);
	}

	fclose(LOG);
	close(LOG_FD);

	/* clean up config */
	free_config(&current_config);

	/* send cancellation requests to worker threads and wait for them to finish */
    if (db_worker) {
	    pthread_cancel(db_worker);
        pthread_join(db_worker, 0);
    }

    if (inotify_worker) {
	    pthread_cancel(inotify_worker);
        pthread_join(inotify_worker, 0);
    }

	PQfinish(db_conn);
}

/* cleanup for initialisation */
void init_cleanup(int err)
{
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

	if (db_conn) {
		PQfinish(db_conn);
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

	snprintf(buf, MAX_LOG_MSG, "stats: %ld packets per second, %ld blocked IPs\n",
			packet_rate(&total_packet_count, &total_handle_time), total_blocked_ips);
	write(LOG_FD, buf, strlen(buf));
}

void gen_log_name(char *name)
{
	time_to_str(time(NULL), name,
			LOG_FILENAME_LENGTH, "log/%Y-%m-%d_%H-%M-%S");
}

/* TODO replace perror() with file, function, line etc. macro */
void open_file(char *name, FILE **file)
{
	*file = fopen(name, "a");
	if (!(*file)) {
		perror("invalid file handle");
		exit(errno);
	}
}

void open_fd(char *name, int *fd)
{
	*fd = open(name, O_RDWR | O_APPEND);
	if (*fd == -1) {
		perror("invalid file descriptor");
		exit(errno);
	}
}

void init_log_file(char *filename)
{
	open_file(filename, &LOG);
	open_fd(filename, &LOG_FD);
}

void init_config_path(char **relative_path, char **config_path, char **config_dir,
		char **config_filename, FILE *LOG)
{
	char *dirc, *basec;
	char *tmp;

	/* set up config path */
	tmp = realpath(*relative_path, NULL);
	if (!tmp) {
		log_error(LOG, "%s: %s\n", *relative_path, strerror(errno));
        return;
	}
    *config_path = strndup(tmp, strlen(tmp)+1);
    free(tmp);

	/* set up config directory and filename using full config path */
	dirc = strndup(*config_path, strlen(*config_path)+1);
	tmp = dirname(dirc);
	*config_dir = strndup(tmp, strlen(tmp)+1);
    free(dirc);

	basec = strndup(*config_path, strlen(*config_path)+1);
	tmp = basename(basec);
	*config_filename = strndup(tmp, strlen(tmp)+1);
    free(dirc);
}

void load_config(char *path)
{
	cJSON *config_json = json_config(path, LOG);
	if (!config_json) {
		log_info(LOG, "no config file at %s\n", path);
	} else {
		apply_config(config_json, &current_config, &config_lock, LOG);
	}
	cJSON_Delete(config_json);
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

    /* block other signals while in the cleanup handler */
    sigaddset(&cleanup_action.sa_mask, SIGINT);
    sigaddset(&cleanup_action.sa_mask, SIGTERM);
    sigaddset(&cleanup_action.sa_mask, SIGUSR1);

	cleanup_action.sa_flags = 0;

	stats_action.sa_handler = print_stats;
	sigemptyset(&stats_action.sa_mask);
	stats_action.sa_flags = SA_RESTART;

	/* sigaction() returns 0 on success, -1 on error and sets errno to indicate
	 * the error */
	if (sigaction(SIGINT, &cleanup_action, NULL) == -1) {
		log_error(LOG, "SIGINT handler: %s\n", strerror(errno));
		exit(errno);
	}

	if (sigaction(SIGTERM, &cleanup_action, NULL) == -1) {
		log_error(LOG, "SIGTERM handler: %s\n", strerror(errno));
		exit(errno);
	}

	if (sigaction(SIGUSR1, &stats_action, NULL) == -1) {
		log_error(LOG, "SIGUSR handler: %s\n", strerror(errno));
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

	if (*use_db_thread)
		log_debug(LOG, "database worker enabled\n");
}


int get_bpf_map_fd(struct bpf_object *obj, char *name) {
	struct bpf_map *map;

	map = bpf_object__find_map_by_name(obj, name);
	if (!map) {
		log_error(LOG, "cannot find map by name %s\n", name);
		init_cleanup(-1);
	}
	return bpf_map__fd(map);
}

void init_kernel_rb(struct ring_buffer **rb, int fd, void *callback)
{
	*rb = ring_buffer__new(fd, callback, NULL, NULL);
	if (!*rb) {
		err = -1;
		log_error(LOG, "failed to create kernel ring buffer (fd %d)\n", fd);
		init_cleanup(err);
	}
}

void init_user_rb(struct user_ring_buffer **rb, int fd)
{
	*rb = user_ring_buffer__new(fd, NULL);
	if (!*rb) {
		err = -1;
		log_error(LOG, "failed to create user ring buffer (fd %d)\n", fd);
		init_cleanup(err);
	}
}

void init_db_thread(void *function, struct db_thread_args *args)
{
		int res = pthread_create(&db_worker, NULL,
				function , args);
		if (res != 0) {
			log_error(LOG, "%s\n", "db_worker pthread_create failed");
			cleanup();
			exit(res);
		}
}

void init_inotify_thread(void *function, struct inotify_thread_args *args)
{
	int res = pthread_create(&inotify_worker, NULL,
			function, args);
	if (res != 0) {
		log_error(LOG, "%s\n", "config_worker pthread_create failed");
		cleanup();
		exit(res);
	}
}

void report_flag_based_alert(int alert_type, struct key *key, struct value *val,
		char *ip_str, int dst_port)
{
	if (alert_type == types.XMAS_SCAN) {
		log_alert(LOG, "nmap Xmas scan detected from %s (port %d)!\n",
				ip_str, dst_port);
	} else if (alert_type == types.FIN_SCAN) {
		log_alert(LOG, "nmap FIN scan detected from %s (port %d)!\n",
				ip_str, dst_port);
	} else if (alert_type == types.NULL_SCAN) {
		log_alert(LOG, "nmap NULL scan detected from %s (port %d)!\n",
				ip_str, dst_port);
	}

	if (use_db_thread) {
		queue_work(&task_queue_head, &task_queue_lock, &task_queue_cond,
				 alert_type, types, key, val, dst_port, LOG);
	} else {
		db_write_scan_alert(db_conn, alert_type, types, key, val, NULL, dst_port, LOG);
	}
}

void report_port_based_alert(int alert_type, struct key *key, struct value *val,
		char *ip_str, int port_threshold)
{
	struct port_range *range;

	log_alert(LOG, "port scan (%d or more ports) detected from %s!\n",
			port_threshold, ip_str);

	if (use_db_thread) {
		queue_work(&task_queue_head, &task_queue_lock, &task_queue_cond,
				alert_type, types, key, val, 0, LOG);
	} else {
		range = lookup_port_range(val);
		db_write_scan_alert(db_conn, alert_type, types, key, val, range, 0, LOG);
		free(range);
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
			perror("memory allocation failed");
			cleanup();
			exit(1);
		}


		while (token) {
			port_list[index++] = atoi(token);
			token = strtok(NULL, delim);
		}
		free(buffer);
	} else {
		log_error(LOG, "failed to open file %s\n", filename);
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

void report_blocked_ip(struct key *key, struct value *val, char *ip_str)
{
	log_alert(LOG, "blacklisting %s\n", ip_str);
	submit_ip_entry(key->src_ip, BLACKLIST);

	if (use_db_thread) {
		queue_work(&task_queue_head, &task_queue_lock, &task_queue_cond,
				UNDEFINED, types, key, val, UNDEFINED, LOG);
	} else {
		db_write_blocked_ip(db_conn, key, val, LOG);
	}
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

__attribute__((noinline)) int submit_port_entry(__u16 port)
{
	int err = 0;
	struct port_rb_event *e;

	e = user_ring_buffer__reserve(port_rb, sizeof(*e));
	if (!e) {
		err = -errno;
		return err;
	}

	/* fill out ring buffer sample */
	e->port_num = port;

	user_ring_buffer__submit(port_rb, e);
	return err;
}

void submit_port_list()
{
	pthread_rwlock_rdlock(&config_lock);
	if (current_config.whitelist_port) {
		for (int i = 0; i < current_config.whitelist_port->size; i++) {
			submit_port_entry(current_config.whitelist_port->entries[i]);
		}
	}
	pthread_rwlock_unlock(&config_lock);
}

__attribute__((noinline)) int submit_config()
{
	int err = 0;
	struct config_rb_event *e;

	e = user_ring_buffer__reserve(config_rb, sizeof(*e));
	if (!e) {
		err = -errno;
		return err;
	}

	log_debug(LOG, "%s\n", "submitting config");

	/* fill out ring buffer sample */
	pthread_rwlock_rdlock(&config_lock);
	e->block_src = current_config.block_src;
	e->redirect_ip = current_config.redirect_ip;
	e->dry_run = current_config.dry_run;
	pthread_rwlock_unlock(&config_lock);

	user_ring_buffer__submit(config_rb, e);

	return err;
}

/* called for each packet sent through the ring buffer */
int handle_event(void *ctx, void *data, size_t data_sz)
{
    char address[MAX_ADDR_LEN];
    __u8 protocol;
	int dst_port, err;
	int port_threshold, packet_threshold, alert_threshold, scan_type;

	/* did this packet cause an alert? (used to determine whether to check alert
	 * threshold) */
	bool is_alert = false;
	bool flagged = false;  /* did this IP get flagged? */

	struct timespec start_time, end_time;

	struct xdp_rb_event *e = data;
	struct key *current_key;
	struct value *new_val;

	current_key = malloc(sizeof(struct key));
	if (!current_key) {
		perror("memory allocation failed");
		err = errno;
		cleanup();
		exit(err);
	}

	new_val = malloc(sizeof(struct value));
	if (!new_val) {
		perror("memory allocation failed");
		err = errno;
		cleanup();
		exit(err);
	}

	get_clock_time(&start_time);

	/* extract data from IP and TCP headers */
	/* source IP address */
	current_key->src_ip = src_addr(&e->ip_header);
	ip_to_str(current_key->src_ip, address);

    protocol = protocol_num(&e->ip_header);
    /* get destination port depending on protocol */
    switch (protocol) {
        case TCP_PNUM:
            dst_port = tcp_dst_port(&e->tcp_header);
            break;
        case UDP_PNUM:
            dst_port = udp_dst_port(&e->udp_header);
            break;
    }

	/* set up hash table entry */
	init_entry(packet_table, current_key, new_val, dst_port, protocol);

	/* read packet and port thresholds from config file */
	pthread_rwlock_rdlock(&config_lock);
	port_threshold = current_config.port_threshold;
	packet_threshold = current_config.packet_threshold;
	alert_threshold = current_config.alert_threshold;
	pthread_rwlock_unlock(&config_lock);

    /* detect flag-based scans (TCP only) */
    if (protocol == TCP_PNUM) {
        scan_type = flag_based_scan(&e->tcp_header, types);
        /* check packet threshold */
        if (scan_type) {
            if (new_val->total_packet_count >= packet_threshold) {
                report_flag_based_alert(scan_type, current_key, new_val, address, dst_port);
                is_alert = true;
            }
        }
    }

	log_debug(LOG, "local port = %-5d port count = %-5d packet count = %-5d src IP = %s\n",
				dst_port, new_val->total_port_count, new_val->total_packet_count, address);

    /* detect port-based scans (all packets) */
	if (new_val->total_port_count >= port_threshold) {
		is_alert = true;
		report_port_based_alert(types.PORT_SCAN, current_key, new_val, address, port_threshold);
	}

	if (is_alert) {
		/* increment alert count */
		new_val->alert_count++;
		/* check current number of alerts */
		log_debug(LOG, "alert count for %s: %d\n", address, new_val->alert_count);

		/* flag IP if alert threshold reached */
		if (new_val->alert_count >= alert_threshold) {
			flagged = true;
			total_blocked_ips ++;  /* update count for stats */
			report_blocked_ip(current_key, new_val, address);
		}
	}

	/* update hash table */
	update_entry(packet_table, current_key, new_val, flagged);

	get_clock_time(&end_time);
	update_total_time(&start_time, &end_time, &total_handle_time);
	/* update total packet count */
	total_packet_count++;

	free(current_key);
	free(new_val);

	return 0;
}

void handle_inotify_events(int fd, const char *target_path, const char *target_filename,
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
			log_error(LOG, "read inotify fd failed: %s\n", strerror(errno));
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
				cJSON *config_json = json_config(target_path, LOG);
				if (!config_json) {
					log_error(LOG, "%s\n", "invalid JSON");
				} else {
					apply_config(config_json, current_config, lock, LOG);

					/* submit config: action, and black/whitelisted IPs */
					submit_config();
					submit_ip_list();
                    submit_subnet_list();
					submit_port_list();

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

	const char *CONFIG_PATH = ctx->config_path;
	const char *CONFIG_DIR = ctx->config_dir;
	const char *CONFIG_FILENAME = ctx->config_filename;

	/* create inotify file descriptor */
	inotify_fd = inotify_init();
	if (inotify_fd == -1) {
		log_error(LOG, "inotify_init: %s\n", strerror(errno));
	}

	/* watch for changes to files in the config directory
	 * wd = watch file descriptor */
	wd = inotify_add_watch(inotify_fd, CONFIG_DIR, IN_CLOSE_WRITE);
	if (wd == -1) {
		log_error(LOG, "inotify: cannot watch '%s': %s\n",
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
					log_error(LOG, "inotify poll: %s\n", strerror(errno));
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
				handle_inotify_events(inotify_fd, CONFIG_PATH, CONFIG_FILENAME,
						current_config, lock);
			}
		}
	}
}

int main(int argc, char *argv[])
{
	struct args init_args;
	char *config_dir, *config_path = NULL, *config_filename;

	const char *DEFAULT_CONFIG_PATH = "config/default.json";

    /* map file descriptors */
	int ip_list_fd, subnet_list_fd, port_list_fd, config_hash_fd;

    /* ring buffers */
    int xdp_rb_fd, ip_rb_fd, subnet_rb_fd, port_rb_fd, config_rb_fd;

	/* arguments to pass to database and inotify worker threads */
	struct db_thread_args db_worker_args;
    bool use_inotify_thread = true;
	struct inotify_thread_args inotify_worker_args;

	/* parse command-line arguments */
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
        pr_err("error setting up interface %s: %s\n", init_args.interface,
                strerror(errno));
		exit(errno);
	}

	/* initialise and open log file: can use logging functions instead of prints
	 * from here onwards */
	init_log_file(init_args.log_file);

	/* initialise configuration */
	fallback_config(&current_config, &config_lock);
	/* load default config file */
	log_debug(LOG, "loading default config from %s\n", DEFAULT_CONFIG_PATH);
	load_config((char *) DEFAULT_CONFIG_PATH);

	/* load argument-specified config file */
	init_config_path(&init_args.config_file, &config_path, &config_dir,
            &config_filename, LOG);

    if (config_path) {
	    log_info(LOG, "loading config from %s\n", config_path);
	    load_config(config_path);
    } else {
        /* use default config path, directory, and filename */
        init_config_path((char **) &DEFAULT_CONFIG_PATH,
                &config_path, &config_dir, &config_filename, LOG);
        /* default config not found */
        if (!config_path) {
            log_info(LOG, "no default config at %s\n",
                    DEFAULT_CONFIG_PATH);
            use_inotify_thread = false;
        }
    }

	/* apply dry run setting from command-line arguments */
	current_config.dry_run = init_args.dry_run;
	log_info(LOG, "dry run = %d\n", current_config.dry_run);

	/* cleanup and stats signal handlers */
	setup_signal_handlers();

	/* determine whether we're going to have a database worker thread */
	get_thread_env(&use_db_thread);

    /* load and attach XDP program */
    err = init_xdp_prog(&xdp_obj, init_args.bpf_obj_file, "process_packet",
            ifindex, xdp_flags, LOG);
	if (err < 0)
		goto fail;

	/* get IP hash map file descriptor so it can be shared with the
	 * corresponding uretprobe */
	ip_list_fd = get_bpf_map_fd(xdp_obj, "ip_list");
	subnet_list_fd = get_bpf_map_fd(xdp_obj, "subnet_list");
	port_list_fd = get_bpf_map_fd(xdp_obj, "port_list");

    /* load and attach IP list uretprobe */
	ip_uretprobe_args.uretprobe_obj = &ip_uretprobe_obj;
	ip_uretprobe_args.filename = init_args.bpf_obj_file;
	ip_uretprobe_args.bpf_map_fd = ip_list_fd;
	if (init_uretprobe(&ip_uretprobe_args, LOG) <= 0) {
		log_error(LOG, "failed to load uretprobe program from file: %s\n",
				init_args.bpf_obj_file);
		err = -1;
		init_cleanup(err);
	}

    /* load and attach subnet list uretprobe */
	subnet_uretprobe_args.uretprobe_obj = &subnet_uretprobe_obj;
	subnet_uretprobe_args.filename = init_args.bpf_obj_file;
	subnet_uretprobe_args.bpf_map_fd = subnet_list_fd;
	if (init_uretprobe(&subnet_uretprobe_args, LOG) <= 0) {
		log_error(LOG, "failed to load uretprobe program from file: %s\n",
				init_args.bpf_obj_file);
		err = -1;
		init_cleanup(err);
	}

	/* load and attach port list uretprobe */
	port_uretprobe_args.uretprobe_obj = &port_uretprobe_obj;
	port_uretprobe_args.filename = init_args.bpf_obj_file;
	port_uretprobe_args.bpf_map_fd = port_list_fd;
	if (init_uretprobe(&port_uretprobe_args, LOG) <= 0) {
		log_error(LOG, "failed to load uretprobe program from file: %s\n",
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
	config_uretprobe_args.bpf_map_fd = config_hash_fd;
	if (init_uretprobe(&config_uretprobe_args, LOG) <= 0) {
		log_error(LOG, "failed to load uretprobe program from file: %s\n",
				init_args.bpf_obj_file);
		err = -1;
		init_cleanup(err);
	}

	/* set up database */
	db_conn = connect_db("root", "sheriff_logbook", LOG);
	if (!db_conn) {
		err = -1;
		init_cleanup(err);
	}

	types = db_read_alert_type(db_conn, LOG);
	if (!check_alert_type(types)) {
		log_error(LOG, "alert types not found in database\n");
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

	port_rb_fd = get_bpf_map_fd(port_uretprobe_obj, "port_rb");
	init_user_rb(&port_rb, port_rb_fd);

	/* set up config user ring buffer */
	config_rb_fd = get_bpf_map_fd(config_uretprobe_obj,"config_rb");
	init_user_rb(&config_rb, config_rb_fd);

	/* submit initial config to BPF program */
	submit_config(); /* block/redirect blacklisted IPs + dry run mode */
	submit_ip_list(); /* IP blacklist + whitelist */
    submit_subnet_list(); /* subnet blacklist + whitelist */
	submit_port_list(); /* port whitelist */

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
    if (use_inotify_thread) {
	    inotify_worker_args.config_path = strndup(config_path, strlen(config_path)+1);
	    inotify_worker_args.config_dir = strndup(config_dir, strlen(config_dir)+1);
	    inotify_worker_args.config_filename = strndup(config_filename, strlen(config_filename)+1);
        if (!inotify_worker_args.config_path ||
		    !inotify_worker_args.config_dir ||
		    !inotify_worker_args.config_filename) {
            perror("memory allocation failed");
            exit(errno);
        }

    	inotify_worker_args.current_config = &current_config;
    	inotify_worker_args.lock = &config_lock;

	    init_inotify_thread((void *) inotify_thread_work, &inotify_worker_args);
    }

	/* poll ring buffer */
	while (!exiting) {
		err = ring_buffer__poll(xdp_rb, XDP_RB_TIMEOUT);

		/* EINTR = interrupted syscall */
		if (err == -EINTR) {
			continue;
		}

		if (err < 0) {
			log_error(LOG, "ring buffer polling failed: %d\n", err);
			break;
		}
	}

	cleanup();
	return 0;

fail:
	switch (-err) {
		case EBUSY:
		case EEXIST:
			log_error(LOG, "XDP already loaded on device %s\n", init_args.interface);
			break;
		case ENOMEM:
		case EOPNOTSUPP:
			log_error(LOG, "native XDP not supported on device %s, try --skb-mode\n",
					init_args.interface);
			break;
		default:
			log_error(LOG, "XDP attach on %s failed %d: %s\n",
				init_args.interface, err, strerror(-err));
			break;
	}

	return -err;
}
