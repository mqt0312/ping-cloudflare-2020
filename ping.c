#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>

#define NS_IN_S 1000000000L
#define TIMEOUT 1 // One second
#define TYPE_ECHO 8
#define TYPE_ECHO_R 0
#define USAGE "\nUsage: ping <destination> [-t TTL] [-n number of packet]\n" \
              "\t-t=TTL: Set TTL to a specific value (default 64)\n" \
              "\t-n=PACKET_LIMIT: Send only a PACKET_LIMIT number of packet. \n" \
              "\t                 If not specified, ping will send until termination\n\n"
#define PING_PACKET_SIZE 64 // Based on the Linux's ping
#define PING_HEADER_SIZE sizeof(struct ping_header)
#define MAX_IP_LENGTH 256
#define MSG "Hello Cloudflare!" // for testing purpose to distinguish ICMP packets
                                // between Linux ping and my ping. Use a network analyzer
                                // like Wireshark to see the message in the packet
char loop = 1;
int TTL = 64,
    MAX_PKT_CNT = 0;

// Ping packet header per RFC 792 of fixed size PING_HEADER_SIZE (8)
struct ping_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum; // Internet Checksum
    uint16_t identifier; // Specific to timestamp, info or echo (ping)
    uint16_t sequence; // Specific to timestamp, info or echo (ping)
};

// Ping packet of fixed size PING_PACKET_SIZE (64)
struct ping_packet {
    struct ping_header header;
    char msg[PING_PACKET_SIZE - PING_HEADER_SIZE];
};

// SIGINT handler to end the main loop
void sigint_handler(int signo) {
    (void) signo;
    loop = 0;
}

unsigned short icmp_checksum(void *b, int len);
char *dns_resolve(char *hostname, struct sockaddr_in *target_addr);
char *dns_resolve_r(char *ip_addr);
int ping_sock_init();
void make_ping_packet(int pkt_cnt, struct ping_packet * p_pkt);
int time_diff(struct timespec *ts_start, struct timespec *ts_end, struct timespec *ret_ts);
int timespec_to_string(struct timespec *ts, char *buf, int length);
long long llsqrt(long long a);
long stddev_time(struct timespec *elapsed, char is_done, int *tot_cnt);
long avg_time(struct timespec *elapsed, char is_done, int *tot_cnt);

// Main loop
int main(int argc, char *argv[]) {
    struct sigaction sa;
    sa.sa_handler = &sigint_handler;
    sigaction(SIGINT, &sa, NULL);
    char *ip, *hostname_r, *hostname;
    char packet_not_sent = 1, is_hostname_r = 1;
    struct sockaddr_in target_addr, received_addr;
    int target_addr_len = sizeof(target_addr);
    unsigned int addr_len;
    // Arg stuff
    int c;
    opterr = 0;
    while ((c = getopt (argc, argv, "t:n:")) != -1) {
        switch (c)
        {
            case 't':
                TTL = atoi(optarg);
                break;
            case 'n':
                MAX_PKT_CNT = atoi(optarg);
                break;
            case '?':
                if (optopt == 't') {
                    fprintf(stderr, "[ERROR] ping: Please specify a TTL value\n");
                }
                if (optopt == 'n') {
                    fprintf(stderr, "[ERROR] ping: Please specify the number of ping packet you want to send\n");
                }
                return EXIT_FAILURE;
            default:
                printf(USAGE);
                return EXIT_FAILURE;
        }
    }
    if (optind < argc) {
        hostname = argv[optind];
    }
    if (!hostname) {
        printf(USAGE);
        return EXIT_FAILURE;
    }
    // Resolve hostname
    if (!(ip = dns_resolve(hostname, &target_addr))) {
        errno = EHOSTUNREACH;
        fprintf(stderr, "[ERROR] ping: A fatal error has occured: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    // If user entered local IP address, no need for reversed hostname
    if (!(hostname_r = dns_resolve_r(ip))) {
        is_hostname_r = 0;
        hostname_r = "";
    }
    // Initiate ping socket
    int p_sock = ping_sock_init();
    if (p_sock < 0) {
        fprintf(stderr, "[ERROR] ping: A fatal error has occured: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    // Initiate total packet and successful packet count
    int pkt_cnt = 0,
            pkt_succ = 0;

    struct ping_packet *p_pkt = (struct ping_packet *) malloc(sizeof(struct ping_packet));
    // Use fixed size array for pretty printing
    char time_elapsed_s[6], time_total_s[8], time_max_s[6], time_min_s[6], time_avg_s[6], time_stddev_s[6];
    // Spawn in a bunch of timespec struct for time calculation.
    struct timespec time_sample1, time_sample2, time_elapsed,
            time_total, time_total_start, time_total_end,
            time_max, time_min, time_avg;

    time_total.tv_sec = 0;
    time_total.tv_nsec = 0;

    time_min.tv_sec = TIMEOUT + 1;
    time_min.tv_nsec = 0;

    time_max.tv_sec = -1;
    time_max.tv_nsec = 0;

    time_avg.tv_sec = 0;
    time_avg.tv_nsec = 0;

    clock_gettime(CLOCK_MONOTONIC_RAW, &time_total_start);

    printf("Pinging %s (%s) %d bytes\n", hostname, ip, PING_PACKET_SIZE+20); // +20 to take into account the IPv4 header
    while (loop) {
        make_ping_packet(pkt_cnt++, p_pkt);
        clock_gettime(CLOCK_MONOTONIC_RAW, &time_sample1);
        // Sending the ping packet
        if (sendto(p_sock, p_pkt, PING_PACKET_SIZE, 0, (struct sockaddr *) &target_addr, sizeof(target_addr)) <= 0) {
            fprintf(stderr, "[ERROR] main: Failed to send ping request packet. Perhaps the connection is down.\n");
        } else {
            packet_not_sent = 0;
        }
        // Somehoe the addr len has to be pointer for the receiving function
        addr_len = sizeof(received_addr);

        // Receiving the ping packet
        if (!packet_not_sent) {
            if (recvfrom(p_sock, p_pkt, PING_PACKET_SIZE, 0, (struct sockaddr *) &received_addr, &addr_len) <= 0) {
                fprintf(stderr, "[ERROR] main: Request timeout\n");
                packet_not_sent = 1;
            }
            clock_gettime(CLOCK_MONOTONIC_RAW, &time_sample2);
        }

        // One-shot while loop to process the output, if any
        while (!packet_not_sent) {
            pkt_succ++;
            // Type verification
            if (p_pkt->header.type != TYPE_ECHO_R) {
                fprintf(stderr, "[ERROR] main: Invalid ping response packet type\n");
                fprintf(stderr, "\tResponse type: %d\n", p_pkt->header.type);
                break;
            }
            // Checksum verification
            uint16_t received_checksum = p_pkt->header.checksum;
            p_pkt->header.checksum = 0;
            uint16_t calculated_checksum = icmp_checksum(p_pkt, PING_PACKET_SIZE);
            if (received_checksum != calculated_checksum) {
                fprintf(stderr, "[ERROR] main: Invalid checksum\n");
                fprintf(stderr, "\tReceived Packet checksum: %x\n", received_checksum);
                fprintf(stderr, "\tCalculated checksum: %x\n", calculated_checksum);
                break;
            }
            // Calculate time elapsed and update stddev and avg function.
            time_diff(&time_sample1, &time_sample2, &time_elapsed);
            stddev_time(&time_elapsed, 0, NULL);
            avg_time(&time_elapsed, 0, NULL);
            // Min time
            if (time_elapsed.tv_sec < time_min.tv_sec ||
                (time_elapsed.tv_sec == time_min.tv_sec && time_elapsed.tv_nsec < time_min.tv_nsec)) {
                time_min.tv_sec = time_elapsed.tv_sec;
                time_min.tv_nsec = time_elapsed.tv_nsec;
            }
            // Max time
            if (time_elapsed.tv_sec > time_max.tv_sec ||
                (time_elapsed.tv_sec == time_max.tv_sec && time_elapsed.tv_nsec > time_max.tv_nsec)) {
                time_max.tv_sec = time_elapsed.tv_sec;
                time_max.tv_nsec = time_elapsed.tv_nsec;
            }

            // Pretty print a single packet's report
            timespec_to_string(&time_elapsed, time_elapsed_s, 6);
            printf("%d bytes from %s (%s): TTL=%d, MAX_PKT=%d seq=%d, checksum=%x, time=%sms\n",
                   PING_PACKET_SIZE, hostname_r, ip, TTL,MAX_PKT_CNT,
                   pkt_cnt, received_checksum, time_elapsed_s);
            break;
        }

        // Main loop's clean up
        packet_not_sent = 1;
        sleep(1);
        // Check to see if there is a
        if (MAX_PKT_CNT > 0 && pkt_cnt >= MAX_PKT_CNT) break;
    }

    // Gathering all the statistics together
    clock_gettime(CLOCK_MONOTONIC_RAW, &time_total_end);
    time_diff(&time_total_start, &time_total_end, &time_total);
    double mdev = pkt_succ ? stddev_time(NULL, 1, &pkt_succ) / 1000.0 : 0;
    double avg = pkt_succ ? avg_time(NULL, 1, &pkt_succ) / 1000000.0 : 0;
    double succ_rate = (double) pkt_succ / (double) pkt_cnt * 100.0;
    // Pretty printing the report
    snprintf(time_stddev_s, 6, "%f", mdev);
    snprintf(time_avg_s, 6, "%f", avg);
    timespec_to_string(&time_total, time_total_s, 8);
    timespec_to_string(&time_min, time_min_s, 6);
    timespec_to_string(&time_max, time_max_s, 6);
    printf("\n------- Stat for %s -------\n", hostname);
    printf("  Total no. of packet: %-6d\n"
           "    Success: %-6d\n"
           "    Lost: %-6d\n"
           "    Success Rate: %2.1f%%\n"
           "  Total time: %sms\n"
           "  Min time: %sms\n"
           "  Max time: %sms\n"
           "  Avg time: %sms\n"
           "  Stddev: %s\n\n",
           pkt_cnt, pkt_succ, pkt_cnt - pkt_succ, succ_rate >= 0 ? succ_rate : 0,
           time_total_s, time_min.tv_sec >= TIMEOUT + 1 ? " N/A " : time_min_s,
           time_max.tv_sec <= -1 ? " N/A " : time_max_s,
           avg <= 0 ? " N/A " : time_avg_s, time_stddev_s);

    // Clean up
    free(p_pkt);
    p_pkt = NULL; // get rid of dangling pointer
    free(ip);
    ip = NULL; // get rid of dangling pointer
    if (is_hostname_r) {
        free(hostname_r);
        hostname_r = NULL; // get rid of dangling pointer
    }
    close(p_sock);

    return EXIT_SUCCESS;
}

// Compute ICMP checksum
unsigned short icmp_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *) buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Resolve hostname. Return a string containing the IPv4 address
char *dns_resolve(char *hostname, struct sockaddr_in *target_addr) {
    char *ret_ip = (char *)malloc(MAX_IP_LENGTH+1);
    struct hostent *he;

    if ((he = gethostbyname(hostname)) == NULL) {
        fprintf(stderr, "[ERROR] dns_resolve: Cannot resolve hostname\n");
        return NULL;
    }
    strcpy(ret_ip, inet_ntoa(*(struct in_addr *) he->h_addr));
    target_addr->sin_family = he->h_addrtype;
    target_addr->sin_port = htons(0);
    target_addr->sin_addr.s_addr = *(long *) (he->h_addr);

    return ret_ip;
}

// Reverse resolve the hostname. Return a string containing the result
char *dns_resolve_r(char *ip_addr) {
    char * ret_hostname_r = (char *) malloc(NI_MAXHOST+1);
    struct sockaddr_in tmp_addr;

    tmp_addr.sin_family = AF_INET;
    tmp_addr.sin_addr.s_addr = inet_addr(ip_addr);
    socklen_t addr_len = sizeof(struct sockaddr_in);

    if (getnameinfo((struct sockaddr *) &tmp_addr, addr_len, ret_hostname_r, NI_MAXHOST, NULL, 0, NI_NAMEREQD)) {
        fprintf(stdout, "[WARNING] dns_resolve_r: Cannot resolve reversed lookup of hostname.\n");
        return NULL;
    }
    return ret_hostname_r;
}

// Setup the socket.
int ping_sock_init() {
    // Open a socket. SOCK_RAW would need both root priv/setcap and manual removal of IPv4
    int p_sock = socket(AF_INET, SOCK_DGRAM,
                        IPPROTO_ICMP);
    if (p_sock < 0) {
        fprintf(stderr, "[ERROR] ping_sock_init: Failed to spawn socket fd\n");
        return -1;
    }
    // Set TTL and timeout setting for socket
    int ttl = TTL;
    struct timespec timeout;
    timeout.tv_sec = TIMEOUT;
    timeout.tv_nsec = 0;

    if (setsockopt(p_sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
        fprintf(stderr, "[ERROR] ping_sock_init: Cannot set TTL\n");
        return -1;
    }
    if (setsockopt(p_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof timeout) !=
        0) { // set timeout so the thing
        fprintf(stderr, "[ERROR] ping_sock_init: Cannot set timeout\n");
        return -1; // exit to prevent long wait
    }

    return p_sock;
}

// (Re)Build the ping packet and increment pkt_cnt
void make_ping_packet(int pkt_cnt, struct ping_packet * p_pkt) {
    p_pkt->header.type = TYPE_ECHO;
    p_pkt->header.code = 0;
    p_pkt->header.identifier = getpid();
    p_pkt->header.sequence = htons(pkt_cnt++);
    memcpy(p_pkt->msg, MSG, sizeof(MSG));
    p_pkt->header.checksum = 0;
    p_pkt->header.checksum = icmp_checksum(p_pkt, PING_PACKET_SIZE);
}

// Compute the difference between two timespec
int time_diff(struct timespec *ts_start, struct timespec *ts_end, struct timespec *ret_ts) {
    ret_ts->tv_sec = ts_end->tv_sec - ts_start->tv_sec;
    ret_ts->tv_nsec = ts_end->tv_nsec - ts_start->tv_nsec;
    if (ret_ts->tv_nsec < 0) {
        ret_ts->tv_nsec += NS_IN_S;
        ret_ts->tv_sec--;
    }
    return 0;
}

// Convert timespec to string
int timespec_to_string(struct timespec *ts, char *buf, int length) {
    snprintf(buf, length, "%f", (ts->tv_sec * 1000.0) + (ts->tv_nsec / 1000000.0));
    return 0;
}

// Compute sqrt and return a long long
long long llsqrt(long long a) {
    long long prev = ~((long long) 1 << 63);
    long long x = a;
    if (x > 0) {
        while (x < prev) {
            prev = x;
            x = (x + (a / x)) / 2;
        }
    }
    return x;
}

// Compute standard deviation for the packets' time_elapsed
long stddev_time(struct timespec *elapsed, char is_done, int *tot_cnt) {
    static long long sum1_us = 0, sum2_us = 0;
    if (is_done) {
        sum1_us /= *tot_cnt;
        sum2_us /= *tot_cnt;
        return llsqrt(sum2_us - sum1_us * sum1_us);
    }
    long long elapsed_time_us = (elapsed->tv_sec * 1000000) + (elapsed->tv_nsec / 1000);
    sum1_us += elapsed_time_us;
    sum2_us += elapsed_time_us * elapsed_time_us;

}

// Compute the average for the packets' time_elapsed
long avg_time(struct timespec *elapsed, char is_done, int *tot_cnt) {
    static long long sum_ns = 0;
    if (is_done) {
        return sum_ns / *tot_cnt;
    }
    long long elapsed_time_ns = (elapsed->tv_sec * NS_IN_S) + elapsed->tv_nsec;
    sum_ns += elapsed_time_ns;
}