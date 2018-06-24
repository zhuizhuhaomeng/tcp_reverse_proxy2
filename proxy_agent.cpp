/**
 *
 * 代理转发
 *
 * Usage
 *
 * make
 * ./proxy_agent -s 127.0.0.1:8888 -t 127.0.0.1:22 -c 10
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <time.h>
#include <locale.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>

#define max(m,n) ((m) > (n) ? (m) : (n))
#define SLOG(fmt, ...) message(__FILE__, __LINE__, fmt, ##__VA_ARGS__)

void message(const char *filename, int line, const char *fmt, ...)
{
    char sbuf[1024], tbuf[30];
    va_list args;
    time_t now;
    uint len;

    va_start(args, fmt);
    len = vsnprintf(sbuf, sizeof(sbuf), fmt, args);
    va_end(args);

    if (len >= sizeof(sbuf)) {
        memcpy(sbuf + sizeof(sbuf) - sizeof("..."), "...", sizeof("...") - 1);
        len = sizeof(sbuf) - 1;
    }
    sbuf[len] = '\0';

    now = time(NULL);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %X", localtime(&now));
    fprintf(stderr, "%s|%u|%s,%d|%s\n", tbuf, getpid(), filename, line, sbuf);
}

typedef struct {
    char proxy_server[16];
    int proxy_port;
    char target_server[16];
    int target_port;
    int running;
    int daemon;
    pthread_mutex_t lock;
    bool add_connection;
} ProxyServer;

ProxyServer ps = { "127.0.0.1", 8888, "127.0.0.1", 9999, 1, 10, 0, 0 };


bool
GetDnsIp(const char *hostname, struct sockaddr_in *inaddr)
{
    bool ret = false;
    struct addrinfo hint;
    struct addrinfo *info;
    struct addrinfo *point = NULL;

    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hint.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hint.ai_flags = 0;
    hint.ai_protocol = 0;          /* Any protocol */
    info = NULL;

    if (getaddrinfo(hostname, NULL, &hint, &info) != 0) {
        if (info) {
            freeaddrinfo(info);
        }

        return false;
    }

    point = info;
    while (point != NULL) {
        if (point->ai_family == AF_INET) {
            *inaddr = *(struct sockaddr_in *)point->ai_addr;
            ret = true;
            break;
        }

        point = point->ai_next;
    }

    freeaddrinfo(info);
    return ret;
}


#define SNCODE_PATH "/usr/local/vpnagent/glicense/conf/SNCODE"

bool ReadSnCode(char *sn)
{
    FILE *fp = NULL;
    int len = 0;
    int index = 0;

    if ((fp = fopen(SNCODE_PATH, "r")) != NULL) {
        len = fread(sn, 1, 256, fp);
        if (ferror(fp)) {
            SLOG("Have not UserName.");
            fclose(fp);
            return false;
        }
        fclose(fp);
        while (sn[index] != '\n' && index < len) {
            index++;
        }
        sn[index] = '\0';
        SLOG("SNCODE: [%s][%d]", sn, len);
        return true;
    }
    return false;
}

void
SetKeepalive(int sock, uint32_t idle, uint32_t interval, uint32_t count)
{
    int keepalive = 1;          // 开启keepalive属性
    int keepidle = idle > 0 ? idle : 60;        // 如该连接在60秒内没有任何数据往来,则进行探测
    int keep_interval = interval > 0 ? interval : 5;    // 探测时发包的时间间隔为5 秒
    int keep_count = count > 0 ? count : 3;     // 探测尝试的次数.如果第1次探测包就收到响应了,则后2次的不再发.

    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive));
    setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, (void *)&keepidle, sizeof(keepidle));
    setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, (void *)&keep_interval, sizeof(keep_interval));
    setsockopt(sock, SOL_TCP, TCP_KEEPCNT, (void *)&keep_count, sizeof(keep_count));
}

void signal_handle(int sig)
{
    ps.running = 0;
}

void show_usage(const char *name)
{
    fprintf(stderr, "sshclient--------(7777)proxy_server(8888)--------proxy_agent-------(22)ssh\n");
    fprintf(stderr, "Usage like %s -s 127.0.0.1:8888 -t 127.0.0.1:9999 -c 10 -d\n", name);
}

int connect_server(const char *host, int port)
{
    struct sockaddr_in serv_addr;
    memset(&serv_addr, '0', sizeof(serv_addr));
    if (GetDnsIp(host, &serv_addr) == false) {
        SLOG("get dns name orror %s", host);
        return -1;
    }

    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd == -1) {
        SLOG("connect server %s:%d failed", host, port);
        return cfd;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port   = htons(port);

    if (connect(cfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
        SLOG("connect server %s:%d failed", host, port);
        close(cfd);
        return -1;
    }

    if (fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL, 0) | O_NONBLOCK) == -1) {
        SLOG("set connect server %s:%d nonblocking failed", host, port);
        close(cfd);
        return -1;
    }
    SetKeepalive(cfd, 60, 5, 3);

    SLOG("connect server %s:%d success", host, port);

    return cfd;
}

int sendAll(int fd, char *buf, int n)
{
    int ret;
    fd_set writefds, exceptfds;

    int m = 0;
    while (1) {
        ret = write(fd, buf + m, n - m);
        if (ret <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                FD_ZERO(&writefds);
                FD_ZERO(&exceptfds);

                FD_SET(fd, &writefds);
                FD_SET(fd, &exceptfds);
                ret = select(fd + 1, NULL, &writefds, &exceptfds, NULL);
            } else {
                return -1;
            }
            continue;
        }
        m += ret;
        if (m == n) {
            break;
        }
    }
    return 0;
}

void *agent_thread_func(void *arg)
{
    int cfd = -1;
    int    tfd = -1;
    int    nfds = -1;
    int    ready = -1;
    int    n = 0;
    int wait_flag = 1;
    char sn[512] = "unknown";

    cfd = connect_server(ps.proxy_server, ps.proxy_port);
    if (cfd < 0) {
        return NULL;
    }
    ReadSnCode(sn);
    write(cfd, sn, strlen(sn));

    fd_set readfds, exceptfds;
    char buf[1024];

    while (ps.running) {
        FD_ZERO(&readfds);
        FD_ZERO(&exceptfds);

        FD_SET(cfd, &readfds);
        FD_SET(cfd, &exceptfds);

        nfds = max(0, cfd);
        if (tfd != -1) {
            nfds = max(nfds, tfd);
            FD_SET(tfd, &readfds);
            FD_SET(tfd, &exceptfds);
        }

        ready = select(nfds + 1, &readfds, NULL, &exceptfds, NULL);
        if (ready < 0 && errno == EINTR) {
            continue;
        }

        if (ready <= 0) {
            SLOG("select read event failed");
            break;
        }

        if (FD_ISSET(cfd, &exceptfds)) {
            goto endthread;
        }

        if (FD_ISSET(cfd, &readfds)) {
            SLOG("trigger proxy read");
            if (tfd == -1) {
                SLOG("trigger target connect");
                tfd = connect_server(ps.target_server, ps.target_port);
                if (tfd < 0) {
                    goto endthread;
                }
            }
            if (wait_flag) {
                wait_flag = 0;
                int flag;
                pthread_mutex_lock(&ps.lock);
                ps.add_connection = true;
                pthread_mutex_unlock(&ps.lock);
                n = read(cfd, &flag, sizeof(int));
                if (flag != 0x11223344) {
                    SLOG("invalid flag");
                    goto endthread;
                }
                SLOG("recv start flag");
            }

            while ((n = read(cfd, buf, sizeof(buf))) > 0) {
                if (sendAll(tfd, buf, n) != 0) {
                    goto endthread;
                }
            }

            if (n == 0) {
                goto endthread;
            }
        }

        if (FD_ISSET(tfd, &readfds)) {
            while ((n = read(tfd, buf, sizeof(buf))) > 0) {
                if (sendAll(cfd, buf, n) != 0) {
                    goto endthread;
                }
            }

            if (n == 0) {
                goto endthread;
            }
        }
    }

endthread:

    if (cfd > 0) {
        close(cfd);
    }

    if (tfd > 0) {
        close(tfd);
    }

    SLOG("child_process end");
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        show_usage((const char *)argv[0]);
        return 1;
    }

    int c;
    while ((c = getopt(argc, argv, "dhs:t:")) != -1) {
        switch (c) {
        case 's':
            if (sscanf(optarg, "%[0-9.]:%d", ps.proxy_server, &ps.proxy_port) != 2) {
                show_usage((const char *)argv[0]);
                return 1;
            }
            break;
        case 't':
            if (sscanf(optarg, "%[0-9.]:%d", ps.target_server, &ps.target_port) != 2) {
                show_usage((const char *)argv[0]);
                return 1;
            }
            break;
        case 'd':
            ps.daemon = 1;
            break;
        default:
            show_usage((const char *)argv[0]);
            return 1;
        }
    }

    SLOG("proxyagent would to connect %s:%d for %s:%d", ps.proxy_server, ps.proxy_port, ps.target_server, ps.target_port);

    signal(SIGINT,  signal_handle);
    signal(SIGTERM, signal_handle);

    if (ps.daemon) {
        switch (fork()) {
        case -1:
            break;
        case 0:
            break;
        default:
            _exit(0);
        }

        setsid();
        umask(0);
        close(0);
        close(1);
        close(2);
    }

    ps.running = 1;
    ps.add_connection = false;
    pthread_mutex_init(&ps.lock, NULL);

    pthread_t thid;
    pthread_attr_t threadAttr;
    pthread_attr_init(&threadAttr);
    pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thid, &threadAttr, agent_thread_func, NULL);

    while (ps.running) {
        sleep(1);
        pthread_mutex_lock(&ps.lock);
        if (ps.add_connection) {
            pthread_create(&thid, &threadAttr, agent_thread_func, NULL);
            ps.add_connection = false;
        }
        pthread_mutex_unlock(&ps.lock);
    }

    SLOG("parent_exit|%u", getpid());

    return 0;
}
