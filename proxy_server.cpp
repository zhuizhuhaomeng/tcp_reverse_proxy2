/*******************************************************************
 *
 *    DESCRIPTION:
 *
 *    AUTHOR:
 *
 *    HISTORY:
 *
 *    DATE:2018/6/24
 *
 *******************************************************************/

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>
#include <map>
#include <string>


/**
 *    ssh_client ----(random) proxy_server(8888) ---- proxy_agent ---- ssh_server
 */

using std::string;
using std::multimap;
using std::map;

#define MAX_SN_LEN  32
#define MIN_SN_LEN  5

static struct event_base *base;
static struct sockaddr_storage agent_connect_addr;
static struct sockaddr_in client_connect_addr;
static int connect_to_addrlen;
typedef struct {
    char http_addr[32];
    int http_port;  //使用sscanf解析，请勿修改成unsigned short
    int running;
    int daemon;
    pid_t master_pid;
} ProxyServer;

typedef enum proxy_session_state {
    SESSION_STATE_INIT,
    SESSION_STATE_RECV_SN,
    SESSION_STATE_CLIENT_CONNECTED,
} proxy_session_state;

void message(const char *filename, int line, const char *fmt, ...);
static void agent_readcb(struct bufferevent *bev, void *ctx);
static void agent_writecb(struct bufferevent *bev, void *ctx);
static void agent_eventcb(struct bufferevent *bev, short what, void *ctx);
static void client_readcb(struct bufferevent *bev, void *ctx);
static void client_writecb(struct bufferevent *bev, void *ctx);
static void client_eventcb(struct bufferevent *bev, short what, void *ctx);
#define SLOG(fmt, ...) message(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

class proxy_session {
public:
    string sncode;
    string listen_addr;
    proxy_session_state state;
    unsigned short bind_port;
    int client_fd;
    int agent_fd;
    struct bufferevent *client_be;
    struct bufferevent *agent_be;
    struct evconnlistener *listener;

    proxy_session()
    {
        state = SESSION_STATE_INIT;
        bind_port = 0;
        client_fd = -1;
        agent_fd = -1;
        client_be = NULL;
        agent_be = NULL;
        listener = NULL;
        SLOG("create session %p", this);
    }

    ~proxy_session()
    {
        SLOG("delete session %p", this);
        if (client_be) {
            bufferevent_free(client_be);
        }
        if (agent_be) {
            bufferevent_free(agent_be);
        }
        if (listener) {
            evconnlistener_free(listener);
        }
    }
};


static multimap<string, proxy_session *> session_map;

#define max(m,n) ((m) > (n) ? (m) : (n))

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
    fprintf(stderr, "%s|%u|%s:%d|%s\n", tbuf, getpid(), filename, line, sbuf);
}

ProxyServer ps = { "", 0, 1, 0, 0 };


void
enable_keepalive(int sock, uint32_t idle, uint32_t interval, uint32_t count)
{
    int keepalive = 1;          // 开启keepalive属性
    int keep_idle = idle;        // 如该连接在60秒内没有任何数据往来,则进行探测
    int keep_interval = interval;    // 探测时发包的时间间隔为5 秒
    int keep_count = count;     // 探测尝试的次数.如果第1次探测包就收到响应了,则后2次的不再发.

    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive));
    setsockopt(sock, SOL_TCP, TCP_KEEPIDLE, (void *)&keep_idle, sizeof(keep_idle));
    setsockopt(sock, SOL_TCP, TCP_KEEPINTVL, (void *)&keep_interval, sizeof(keep_interval));
    setsockopt(sock, SOL_TCP, TCP_KEEPCNT, (void *)&keep_count, sizeof(keep_count));
}

void show_usage(const char *name, const char *reason)
{
    fprintf(stderr, "\n\n");
    if (reason != NULL) {
        fprintf(stderr, "    error: %s\n\n", reason);
    }
    fprintf(stderr, "    ssh_client ----(random) proxy_server(8888) ---- proxy_agent ---- ssh_server\n");
    fprintf(stderr, "    Usage like %s -r 127.0.0.1:80 -t 127.0.0.1:8888 -d\n", name);
    fprintf(stderr, "\n\n");
    exit(0);
}

//应用层的缓存尽可能的小，由系统内核进行缓存
#define MAX_OUTPUT (128*1024)

const char *get_error_str(short what)
{
    switch (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
    case BEV_EVENT_EOF:
        return "EOF";

    case BEV_EVENT_ERROR:
        return "ERROR";

    case BEV_EVENT_EOF | BEV_EVENT_ERROR:
        return "EOF|ERROR";
    default:
        return "OK";
    }
}

static void
agent_readcb(struct bufferevent *bev, void *ctx)
{
    char sn[128];
    size_t sz;
    proxy_session *session = (proxy_session *)ctx;

    if (session->state == SESSION_STATE_INIT) {
        sz = bufferevent_read(session->agent_be, sn, sizeof(sn));
        if (sz > MAX_SN_LEN || sz < MIN_SN_LEN) {
            delete session;
            return;
        }
        sn[sz] = '\0';
        session->sncode = sn;
        session->state = SESSION_STATE_RECV_SN;
        session_map.insert(std::make_pair(session->sncode, session));
        SLOG("agent connected with sn %s", sn);
        return;
    }
    if (session->state != SESSION_STATE_CLIENT_CONNECTED) {
        SLOG("recv data in state %d %s", session->state, session->sncode.c_str());
        delete session;
        return;
    }

    struct evbuffer *src = bufferevent_get_input(session->agent_be);
    struct evbuffer *dst = bufferevent_get_output(session->client_be);
    evbuffer_add_buffer(dst, src);

    if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
        SLOG("client_be overflow %sz", evbuffer_get_length(dst));
        bufferevent_setcb(session->client_be, client_readcb, client_writecb, client_eventcb, session);
        bufferevent_setwatermark(session->client_be, EV_WRITE, MAX_OUTPUT/2, MAX_OUTPUT);
        bufferevent_disable(bev, EV_READ);
    }
}

static void
agent_writecb(struct bufferevent *bev, void *ctx)
{
    proxy_session *session = (proxy_session *)ctx;

    /* We were choking the other side until we drained our outbuf a bit.
     * Now it seems drained. */
    bufferevent_setcb(bev, agent_readcb, NULL, agent_eventcb, session);
    bufferevent_enable(session->client_be, EV_READ);
}

static void
agent_eventcb(struct bufferevent *bev, short what, void *ctx)
{
    proxy_session *session = (proxy_session *)ctx;

    SLOG("session %p", session);
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        SLOG("agent error %s", get_error_str(what));
        delete session;
    }
}

static void
agent_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
                struct sockaddr *a, int slen, void *p)
{
    char client_addr[128];
    enable_keepalive(fd, 300, 3, 3);

    proxy_session *session = new proxy_session();
    session->state = SESSION_STATE_INIT;
    session->agent_be = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(session->agent_be, agent_readcb, NULL, agent_eventcb, session);
    bufferevent_enable(session->agent_be, EV_READ | EV_WRITE);
    inet_ntop(a->sa_family, &((struct sockaddr_in *)a)->sin_addr, client_addr, sizeof(client_addr));
    SLOG("session %p client fd %d %s:%d",
         session, fd, client_addr, ntohs(((struct sockaddr_in *)a)->sin_port));
}

void client_free_listener(evutil_socket_t fd, short ev, void *ctx)
{
    struct evconnlistener *listener = (struct evconnlistener *)ctx;
    SLOG("free listener %p", listener);
    evconnlistener_free(listener);
}

static void
client_readcb(struct bufferevent *bev, void *ctx)
{
    proxy_session *session = (proxy_session *)ctx;

    struct evbuffer *src = bufferevent_get_input(session->client_be);
    struct evbuffer *dst = bufferevent_get_output(session->agent_be);
    evbuffer_add_buffer(dst, src);
    if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
        SLOG("agent_be overflow %sz", evbuffer_get_length(dst));
        bufferevent_setcb(session->agent_be, agent_readcb, agent_writecb, agent_eventcb, session);
        bufferevent_setwatermark(session->agent_be, EV_WRITE, MAX_OUTPUT/2, MAX_OUTPUT);
        bufferevent_disable(bev, EV_READ);
    }
}

static void
client_writecb(struct bufferevent *bev, void *ctx)
{
    proxy_session *session = (proxy_session *)ctx;

    bufferevent_setcb(bev, agent_readcb, NULL, agent_eventcb, session);
    bufferevent_enable(session->agent_be, EV_READ);
}

static void
client_eventcb(struct bufferevent *bev, short what, void *ctx)
{
    proxy_session *session = (proxy_session *)ctx;

    SLOG("session %p", session);
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        SLOG("client error %s", get_error_str(what));
        delete session;
    }
}

static void
client_accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
                 struct sockaddr *a, int slen, void *ctx)
{
    char client_addr[128];
    struct timeval tv;
    int start_flag = 0x11223344;
    proxy_session *session = (proxy_session *)ctx;

    session->state = SESSION_STATE_CLIENT_CONNECTED;
    enable_keepalive(fd, 300, 3, 3);
    session->client_be = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    bufferevent_setcb(session->client_be, client_readcb, NULL, client_eventcb, session);
    bufferevent_enable(session->client_be, EV_READ | EV_WRITE);
    bufferevent_write(session->agent_be, &start_flag, sizeof(start_flag));
    inet_ntop(a->sa_family, &((struct sockaddr_in *)a)->sin_addr, client_addr, sizeof(client_addr));
    SLOG("session %p sn %s client fd %d %s:%d",
         session, session->sncode.c_str(), fd, client_addr, ntohs(((struct sockaddr_in *)a)->sin_port));
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    event_base_once(base, -1, EV_TIMEOUT, client_free_listener, session->listener, &tv);
    session->listener = NULL;
}

void http_handler(struct evhttp_request *req, void *arg)
{
    int listen_fd;
    struct sockaddr_in listen_sock;
    socklen_t listen_sock_len;
    char addr_str[128];
    char sock_str[128];
    proxy_session *session;
    string sncode;
    multimap<string, proxy_session *>::iterator it;

    struct evbuffer *buf = evbuffer_new();
    const char *uri = evhttp_request_get_uri(req);

    if (uri == NULL) {
        evbuffer_add_printf(buf, "null uri\n");
        evhttp_send_reply(req, HTTP_BADREQUEST, "BADREQUEST", buf);
        goto _end;
    }

    if (strlen(uri) < MIN_SN_LEN or strlen(uri) > MAX_SN_LEN) {
        evbuffer_add_printf(buf, "invalid uri \"%s\"\n", uri);
        evhttp_send_reply(req, HTTP_BADREQUEST, "BADREQUEST", buf);
        goto _end;
    }

    sncode = string(uri + 1);
    it = session_map.find(sncode);
    if (it == session_map.end()) {
        evbuffer_add_printf(buf, "can not find sncode \"%s\"\n", sncode.c_str());
        evhttp_send_reply(req, HTTP_NOTFOUND, "HTTP_NOTFOUND", buf);
        goto _end;
    }
    session = it->second;
    session_map.erase(it);
    memset(&client_connect_addr, 0, sizeof(client_connect_addr));
    client_connect_addr.sin_family = AF_INET;
    session->listener = evconnlistener_new_bind(base, client_accept_cb, session,
                                                LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE,
                                                -1, (struct sockaddr *)&client_connect_addr, sizeof(client_connect_addr));
    if (session->listener == NULL) {
        SLOG("evconnlistener_new_bind failed %s", strerror(errno));
        delete session;
        return;
    }
    listen_fd = evconnlistener_get_fd(session->listener);
    listen_sock_len = sizeof(listen_sock);
    getsockname(listen_fd, (struct sockaddr *)&listen_sock, &listen_sock_len);
    inet_ntop(listen_sock.sin_family, &listen_sock.sin_addr, addr_str, sizeof(addr_str));
    snprintf(sock_str, sizeof(sock_str), "%s:%d", addr_str, ntohs(listen_sock.sin_port));
    SLOG("evconnlistener_new_bind fd=%d %s", listen_fd, sock_str);
    evbuffer_add_printf(buf, "%s\n", sock_str);
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    session->listen_addr = sock_str;

_end:
    evbuffer_free(buf);
}

int
main(int argc, char **argv)
{
    int i;
    int socklen;
    char addr_str[128];
    struct evconnlistener *listener;

    if (argc < 2) {
        show_usage(argv[0], "not enough argument");
    }

    int c;
    while ((c = getopt(argc, argv, "dhr:t:")) != -1) {
        switch (c) {
        case 'r':
            if (sscanf(optarg, "%[0-9.]:%d", ps.http_addr, &ps.http_port) != 2) {
                show_usage((const char *)argv[0], "http argument error");
                return 1;
            }
            break;
        case 't':
            socklen = sizeof(agent_connect_addr);
            if (evutil_parse_sockaddr_port(optarg, (struct sockaddr *)&agent_connect_addr, &socklen) < 0) {
                show_usage((const char *)argv[0], "agent connect addr error");
            }
            break;
        case 'd':
            ps.daemon = 1;
            break;

        default:
            printf("cccc = %c\n", c);
            show_usage((const char *)argv[0], "unknown argument");
            return 1;
        }
    }

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

    struct sockaddr_in *addr_in = (struct sockaddr_in *)&agent_connect_addr;
    evutil_inet_ntop(addr_in->sin_family, &addr_in->sin_addr, addr_str, sizeof(addr_str));
    SLOG("sproxy server listen on agent connect addr %s:%d", addr_str, ntohs(addr_in->sin_port));


    base = event_base_new();
    if (!base) {
        perror("event_base_new()");
        return 1;
    }

    listener = evconnlistener_new_bind(base, agent_accept_cb, NULL,
                                       LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE,
                                       -1, (struct sockaddr *)&agent_connect_addr, socklen);

    if (!listener) {
        fprintf(stderr, "Couldn't open listener.\n");
        event_base_free(base);
        return 1;
    }

    struct evhttp *http_server = evhttp_new(base);
    assert(http_server != NULL);

    int ret = evhttp_bind_socket(http_server, ps.http_addr, ps.http_port);
    if (ret != 0) {
        fprintf(stderr, "Couldn't open httpserver %s:%d.\n", ps.http_addr, ps.http_port);
        return -1;
    }

    evhttp_set_gencb(http_server, http_handler, NULL);
    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);

    return 0;
}
