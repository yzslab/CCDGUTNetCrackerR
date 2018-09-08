#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include <signal.h>

static pid_t who_lock(int fd);

static void lock_file(int try);

static void init_signal_action();

static void signal_handler(int signal);

static void create_firewall_command(char *device);

static void add_firewall_rule();

static void delete_firewall_rule();

int init_ip_raw_socket(char *device, int protocol);

void package_processor(int raw);

int secure_write(int fd, char *buf, int n);

int tun_alloc(const char *dev, int flags);

static char *strnstr(const char *haystack, const char *needle, size_t len);

static void myLog(const char *, ...);

static void logToSyslog(const char *, ...);

static void nolog(const char *, ...);

static int packet_filter(char *data, size_t len);

static void (*logger)(const char *, ...) = myLog;

static const char *tun_dev_name = "rsck_o";
static const char *lock_file_path = "/tmp/CCDGUTNetCracker.lock";

static const char firewall_mangle_table_prefix[] = "iptables -t mangle ";
const size_t firewall_mangle_table_prefix_length = sizeof(firewall_mangle_table_prefix) - 1;
static const char firewall_mangle_table_suffix[] = " PREROUTING -j DROP -m comment --comment \"CCDGUTNetCracker\" -p tcp --dport 80 -i ";
const size_t firewall_mangle_table_suffix_length = sizeof(firewall_mangle_table_suffix) - 1;

static const char const *firewall_add_forward_allow = "iptables -I FORWARD -m comment --comment \"CCDGUTNetCracker\" -i rsck_o -j ACCEPT";
static const char const *firewall_delete_forward_allow = "iptables -D FORWARD -m comment --comment \"CCDGUTNetCracker\" -i rsck_o -j ACCEPT 2>/dev/null";

static const char *firewall_add_mangle_port_80_drop_command;
static const char *firewall_delete_mangle_port_80_drop_command;

int main(int argc, char *argv[]) {
    if (argc == 1) {
        fprintf(stderr, "Usage: %s device [daemon] [syslog].\n", argv[0]);
        exit(1);
    }

    lock_file(1); // Try to lock file

    // Create a IP raw socket
    int raw_socket_fd = init_ip_raw_socket(argv[1], ETH_P_IP);
    if (raw_socket_fd == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    create_firewall_command(argv[1]);
    delete_firewall_rule();
    init_signal_action();
    add_firewall_rule();

    if (argc >= 3) {
        logger = nolog; // Close log on daemon mode

        // Enable syslog
        if (argc == 4) {
            openlog("CCDGUTNetCracker", LOG_PID, LOG_DAEMON);
            logger = logToSyslog;
        }
        daemon(0, 0);
    }

    lock_file(0); // Lock file really

    package_processor(raw_socket_fd);
    close(raw_socket_fd);

    return 0;
}

static pid_t who_lock(int fd) {
    struct flock flockstr;

    flockstr.l_start = 0;
    flockstr.l_len = 0;
    flockstr.l_whence = SEEK_SET;
    flockstr.l_type = F_WRLCK;

    if (fcntl(fd, F_GETLK, &flockstr) < 0) {
        perror("fcntl()");
        exit(EXIT_FAILURE);
    } else {
        if (flockstr.l_pid > 0)
            return flockstr.l_pid;
        else
            return 0;
    }
}

static void lock_file(int try) {
    int lock_file_fd = open(lock_file_path, O_RDWR | O_CREAT | O_SYNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    pid_t pid_lock;
    struct flock flockstr;

    flockstr.l_start = 0;
    flockstr.l_len = 0;
    flockstr.l_whence = SEEK_SET;
    flockstr.l_type = F_WRLCK;

    if (fcntl(lock_file_fd, F_SETLK, &flockstr) == -1) {
        if ((pid_lock = who_lock(lock_file_fd)) > 0) {
            printf("Another program is running, pid: %ld.\n", (long) pid_lock);
            exit(EXIT_FAILURE);
        } else {
            printf("Unknown flock error.\n");
            exit(EXIT_FAILURE);
        }
    }

    if (try) {
        close(lock_file_fd);
    }
}

static void init_signal_action() {
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGTERM, signal_handler);
}

static void signal_handler(int signal) {
    delete_firewall_rule();
    exit(EXIT_SUCCESS);
}

static void create_firewall_command(char *device) {
    size_t device_length = strlen(device);
    size_t command_buffer_size =
            firewall_mangle_table_prefix_length + 2 + firewall_mangle_table_suffix_length + device_length + 1;
    char *add_command_buffer = malloc(command_buffer_size);
    char *delete_command_buffer = malloc(command_buffer_size + sizeof(" 2>/dev/null") - 1);

    sprintf(add_command_buffer, "%s-I%s%s", firewall_mangle_table_prefix, firewall_mangle_table_suffix, device);
    sprintf(delete_command_buffer, "%s-D%s%s 2>/dev/null", firewall_mangle_table_prefix, firewall_mangle_table_suffix,
            device);

    firewall_add_mangle_port_80_drop_command = add_command_buffer;
    firewall_delete_mangle_port_80_drop_command = delete_command_buffer;

#ifdef ENABLE_LOG
    printf("%s\n%s\n%s\n%s\n", firewall_add_forward_allow, firewall_delete_forward_allow, firewall_add_mangle_port_80_drop_command, firewall_delete_mangle_port_80_drop_command);
#endif
}

static void add_firewall_rule() {
    printf("Add firewall rule.\n");
    if (system(firewall_add_forward_allow) != 0) {
        fprintf(stderr, "Error on add firewall rule to mangle table.");
        exit(EXIT_FAILURE);
    }
    if (system(firewall_add_mangle_port_80_drop_command) != 0) {
        fprintf(stderr, "Error on add firewall rule to filter table.");
        delete_firewall_rule();
        exit(EXIT_FAILURE);
    }
}

static void delete_firewall_rule() {
    printf("Delete firewall rule.\n");
    while (system(firewall_delete_forward_allow) == 0);
    while (system(firewall_delete_mangle_port_80_drop_command) == 0);
}


int init_ip_raw_socket(char *device, int protocol) {
    int raw_socket_fd;
    struct sockaddr_ll sll;
    struct ifreq ifr;

    if ((raw_socket_fd = socket(AF_PACKET, SOCK_RAW, htons(protocol))) < 0) {
        perror("socket()");
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    memset(&ifr, 0, sizeof(ifr));

    strncpy((char *) ifr.ifr_name, device, IFNAMSIZ);
    if ((ioctl(raw_socket_fd, SIOCGIFINDEX, &ifr)) == -1) {
        perror("ioctl()");
        goto CLOSE_RAW_SOCKET_FD;
    }

    // Bind our raw socket to this interface
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(protocol);

    if ((bind(raw_socket_fd, (struct sockaddr *) &sll, sizeof(sll))) < 0) {
        perror("bind()");
        goto CLOSE_RAW_SOCKET_FD;
    }

    goto ON_SUCCESS;

    CLOSE_RAW_SOCKET_FD:
    close(raw_socket_fd);
    return -1;

    ON_SUCCESS:
    return raw_socket_fd;
}

int secure_write(int fd, char *buf, int n) {
    int nwrite = 0, write_return;

    while (n > 0) {
        write_return = write(fd, buf + nwrite, n);
        if (write_return < 0) {
            perror("write()");
            return nwrite;
        }
        nwrite += write_return;
        n -= write_return;
    }

    return nwrite;
}

int tun_alloc(const char *dev, int flags) {
    struct ifreq ifr;
    int fd;
    char *clonedev = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
        perror("ioctl()");
        goto CLOSE_TUN_FD;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket()");
        fd = -1;
        goto CLOSE_TUN_FD;
    }

    bzero(&ifr, sizeof(struct ifreq));
    strcpy(ifr.ifr_name, dev);
    ifr.ifr_flags = IFF_UP | IFF_POINTOPOINT | IFF_RUNNING | IFF_NOARP | IFF_MULTICAST;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl()");
        fd = -1;
        goto CLOSE_SOCK_FD;
    }

    // No error
    goto RETURN_FD;

    CLOSE_SOCK_FD:
    close(sockfd);
    CLOSE_TUN_FD:
    close(fd);
    RETURN_FD:
    return fd;
}

void tcp_checksum(struct iphdr *ip_header, uint16_t *tcp_header, int tcp_length) {
    register unsigned long sum = 0;
    struct tcphdr *tcphdrp = (struct tcphdr *) (tcp_header);
    sum += (ip_header->saddr >> 16u) & 0xFFFFu;
    sum += (ip_header->saddr) & 0xFFFFu;

    sum += (ip_header->daddr >> 16u) & 0xFFFFu;
    sum += (ip_header->daddr) & 0xFFFFu;

    sum += htons(IPPROTO_TCP);

    sum += htons((uint16_t) tcp_length);

    tcphdrp->check = 0;
    while (tcp_length > 1) {
        sum += *tcp_header++;
        tcp_length -= 2;
    }

    if (tcp_length > 0) {
        sum += ((*tcp_header) & htons(0xFF00));
    }

    while (sum >> 16u) {
        sum = (sum & 0xffffu) + (sum >> 16u);
    }
    sum = ~sum;

    tcphdrp->check = (unsigned short) sum;
}

static int packet_filter(char *data, size_t len) {
    static const char get_str[] = "GET /";
    static const char post_str[] = "POST /";
    static const char http_uri_end_str[] = " HTTP/1.1\r\n";
    // static const char http_uri_end_legacy_str[] = " HTTP/1.0\r\n"; // Legacy version
    static const char user_agent_start_keyword[] = "\r\nUser-Agent: ";
    static const char user_agent_start_lower_case_keyword[] = "\r\nuser-agent: ";
    static const char user_agnet_replace_with[] = "Tnega-Resu";

#ifdef ENABLE_LOG
#define buffer_size 4096
    static char string_buffer[buffer_size];
#endif

    int i = 0;

#ifdef ENABLE_LOG
    logger("find header start tag, ");
#endif
    if (len <= sizeof(post_str) + sizeof(http_uri_end_str)) {
#ifdef ENABLE_LOG
        logger("http request header not found [1], ");
#endif
        return 0;
    }

    // Is start with get_str or post_str?
    if (strncmp(data, get_str, sizeof(get_str) - 1) == 0) {
        i += sizeof(get_str) - 1;
    } else if (strncmp(data, post_str, sizeof(post_str) - 1) == 0) {
        i += sizeof(post_str) - 1;
    } else {
#ifdef ENABLE_LOG
        logger("http request header not found [2], ");
#endif
        return 0;
    }

    char *uri_start = data + i;
    size_t size_after_uri_start = len - i;

    /*
    // Is there any header end tag?
#ifdef ENABLE_LOG
    logger("find header end tag, ");
#endif
    char *header_end = strnstr(uri_start, "\r\n\r\n", size_after_uri_start);
    if (header_end == NULL) {
#ifdef ENABLE_LOG
        logger("http request header not found [3], ");
#endif
        return 0;
    }
     */

    // size_t search_size = header_end - uri_start; // Search between uri_start and header_end
    size_t search_size = size_after_uri_start;

    char *uri_end = strnstr(uri_start, http_uri_end_str, search_size);

    if (uri_end == NULL) {
#ifdef ENABLE_LOG
        logger("http request header not found [4], ");
#endif
        return 0;
    }


#ifdef ENABLE_LOG
    // Retrieve request uri
    size_t uri_length = uri_end - uri_start;
    logger("retrieve request uri, ");
    if (uri_length >= buffer_size - 1) {
        logger("request URI too long, ");
    } else {
        memcpy(string_buffer, uri_start, uri_length);
        string_buffer[uri_length] = '\0';
        logger("[%d] URI /", uri_length);
        logger("%s", string_buffer);
        logger(", ");
    }
#endif

     search_size = len - (uri_end - data); // Search after uri_end

    // Find user agent header in http header, hope that the URI won't be too long, so URI and User-Agent can appear in one packet
    char *user_agent_pointer = strnstr(uri_end, user_agent_start_keyword, search_size);
    if (user_agent_pointer == NULL)
        user_agent_pointer = strnstr(uri_end, user_agent_start_lower_case_keyword, search_size);


    if (user_agent_pointer == NULL) {
#ifdef ENABLE_LOG
        logger("key content not found [1], ");
#endif
        return 0;
    }


#ifdef ENABLE_LOG
    char *user_agent_content_start_position = NULL;
    char *user_agent_content_end_position = NULL;

    user_agent_content_start_position = user_agent_pointer + sizeof(user_agent_start_keyword) - 1;
    // Find the end position of user agent header
    user_agent_content_end_position = strnstr(user_agent_content_start_position, "\r\n",
                                              len - (user_agent_content_start_position - data));

    if (user_agent_content_end_position == NULL) {
        logger("key content not found [2], ");
        return 0;
    }

    logger("key content found, ");
    // Retrieve user-agent
    size_t user_agent_length = user_agent_content_end_position - user_agent_content_start_position;
    logger("retrieve User-Agent, ");
    if (user_agent_length >= buffer_size - 1) {
        logger("User-Agent too long, ");
    } else {
        memcpy(string_buffer, user_agent_content_start_position, user_agent_length);
        string_buffer[user_agent_length] = '\0';
        logger("[%d] User-Agnet: ", user_agent_length);
        logger("%s", string_buffer);
        logger(", ");
    }
    logger("replace User-Agent with Tnega-Resu, ");
#endif

    // Simply replace the user agent with blank spaces
    // memset(user_agent_content_start_position, ' ', user_agent_content_end_position - user_agent_content_start_position);

    // Simply replace "User-Agent" with "Tnega-Resu"
    memcpy(user_agent_pointer + 2, user_agnet_replace_with, sizeof(user_agnet_replace_with) - 1);
    return 1;
}

void package_processor(int raw) {
    struct sockaddr_ll packet_info;
    int packet_info_size = sizeof(packet_info_size);
    uint8_t packet_buffer[2048];
    ssize_t len, ip_len, tcp_len, tcp_payload;

    uint8_t *const buffer = packet_buffer + sizeof(struct ethhdr); // buffer point to ip header

    struct iphdr *const ip_header = (struct iphdr *) buffer;
    struct tcphdr *tcp_header;

    const uint16_t port_to_process = htons(80);

    int tap_fd;
    if ((tap_fd = tun_alloc(tun_dev_name, IFF_TUN | IFF_NO_PI)) < 0) {
        fprintf(stderr, "Error connecting to tun/tap interface %s!\n", tun_dev_name);
        exit(1);
    }

    int ip_header_length, tcp_header_length;
    uint8_t *application_layer;

#ifdef ENABLE_LOG
    uint16_t source_port, destination_port;
    char src_ip_buffer[16], dst_ip_buffer[16];
#endif

    while (1) {
        if ((len = recvfrom(raw, packet_buffer, 2048, 0, (struct sockaddr *) &packet_info, &packet_info_size)) == -1) {
            perror("recvfrom()");
        } else {
            ip_len = len - sizeof(struct ethhdr);

            // logger("IPv%d, protocol: %d, ", ip_header->version, ip_header->protocol);
            if (ip_header->version == 4) {
                // TCP is 6
                if (ip_header->protocol == IPPROTO_TCP) {
                    ip_header_length = ip_header->ihl << 2u;
                    tcp_len = ip_len - ip_header_length;

                    tcp_header = (struct tcphdr *) (buffer + ip_header_length);

#ifdef ENABLE_LOG
                    inet_ntop(AF_INET, (uint8_t *) &ip_header->saddr, src_ip_buffer, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, (uint8_t *) &ip_header->daddr, dst_ip_buffer, INET_ADDRSTRLEN);
                    source_port = ntohs(tcp_header->th_sport);
                    destination_port = ntohs(tcp_header->th_dport);
#endif

                    tcp_header_length = tcp_header->doff << 2u;

                    tcp_payload = tcp_len - tcp_header_length;

                    application_layer = (uint8_t *) tcp_header + tcp_header_length;

                    if (tcp_header->th_dport == port_to_process) {
#ifdef ENABLE_LOG
                        logger("Capture a packet of length %d, ", (int) len);
                        logger("ip header length: %d, ", ip_header_length);

                        logger("tcp header length: %d, ", tcp_header_length);

                        logger("src ip: %s, ", src_ip_buffer);
                        logger("dst ip: %s, ", dst_ip_buffer);
                        logger("src port: %d, ", source_port);
                        logger("dst port: %d, ", destination_port);
                        logger("seq: %u, ", ntohl(tcp_header->seq));
                        logger("tcp payload: %zd, ", tcp_payload);
#endif

                        if (tcp_payload > 6) {
#ifdef ENABLE_LOG
                            logger("pass to packet_filter, ");
#endif
                            if (packet_filter(application_layer, tcp_payload)) {
#ifdef ENABLE_LOG
                                logger("recalculate tcp checksum");
#endif

                                tcp_checksum((struct iphdr *) buffer, (uint16_t *) tcp_header, tcp_len);
                            }
                        }

                        // Sent the new packet via tun device
                        secure_write(tap_fd, buffer, ip_len);

#ifdef ENABLE_LOG
                        logger("\n\n");
#endif
                    }
                }
            }
        }
    }
}

static char *strnstr(const char *haystack, const char *needle, size_t len) {
    int i;
    size_t needle_len;

    if (0 == (needle_len = strnlen(needle, len)))
        return (char *) haystack;

    for (i = 0; i <= (int) (len - needle_len); i++) {
        if ((haystack[0] == needle[0]) &&
            (0 == strncmp(haystack, needle, needle_len)))
            return (char *) haystack;

        haystack++;
    }
    return NULL;
}

static void myLog(const char *s, ...) {
    va_list va;
    va_start(va, s);
    vprintf(s, va);
    va_end(va);
    fflush(stdout);
}

static void logToSyslog(const char *s, ...) {
    va_list va;
    va_start(va, s);
    vsyslog(LOG_INFO, s, va);
    va_end(va);
}

static void nolog(const char *s, ...) {

}