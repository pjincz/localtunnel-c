/*
 * Copyright (C) Chizhong Jin
 */


#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <ev.h>

////////////////////////////////////////////////////////////////////////////////
// log

static bool _enable_log = false;

#define log(format, ...) do { \
    if (_enable_log) { \
        time_t t = time(NULL); \
        struct tm *tm_info = localtime(&t); \
        char time_buf[20]; \
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info); \
        fprintf(stderr, "%s] " format "\n", time_buf, ##__VA_ARGS__); \
    } \
} while (0)

#define log_err(format, ...) do { \
    time_t t = time(NULL); \
    struct tm *tm_info = localtime(&t); \
    char time_buf[20]; \
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info); \
    fprintf(stderr, "%s] " format "\n", time_buf, ##__VA_ARGS__); \
} while (0)

////////////////////////////////////////////////////////////////////////////////
// alloc

void *lt_alloc_and_clean(int len) {
    void *mem = malloc(len);
    if (!mem) {
        log_err("crit error, malloc failed");
        exit(1);
    }
    memset(mem, 0, len);
    return mem;
}

#define lt_alloc(type) (type*)lt_alloc_and_clean(sizeof(type))
#define lt_alloc_array(type, n) (type*)lt_alloc_and_clean(sizeof(type) * (n))

char *lt_strdup(const char* str) {
    char *s2 = strdup(str);
    if (!s2) {
        log_err("crit error, strdup failed");
        exit(1);
    }
    return s2;
}

////////////////////////////////////////////////////////////////////////////////
// lt_buf_t

typedef struct {
    size_t size;
    size_t cap;
    char *buf;
} lt_buf_t;

void cleanup_buf(lt_buf_t *buf) {
    free(buf->buf);
}

size_t
ls_buf_write(const void *ptr, size_t size, size_t nmemb, void *userdata) {
    lt_buf_t *buf = userdata;

    size_t new_size = buf->size + size * nmemb;
    if (new_size > buf->cap) {
        size_t new_cap = buf->cap ? buf->cap : new_size;
        while (new_cap < new_size) {
            new_cap *= 2;
        }
        buf->buf = realloc(buf->buf, new_cap);
        if (!buf->buf) {
            log_err("realloc failed");
            return 0;
        }
        buf->cap = new_cap;
    }
    memcpy(buf->buf + buf->size, ptr, size * nmemb);
    buf->size = new_size;
    return size * nmemb;
}

////////////////////////////////////////////////////////////////////////////////
// connection

#define LT_CONN_ESTABLISHED  101
#define LT_CONN_CONN_ERROR   102
#define LT_CONN_READ_AVIL    103
#define LT_CONN_WRITE_AVIL   104
#define LT_CONN_HUP          105
#define LT_CONN_CLOSE        106
#define LT_CONN_DESTROY      107

struct connection_s;

typedef void (*lt_conn_callback)(struct connection_s*, void *, int);

typedef struct writing_task_s {
    char *data;
    int len;
    int written;

    bool freedata;

    struct writing_task_s *next;
} writing_task_t;

typedef struct lt_conn_handler_s {
    lt_conn_callback cb;
    void *data;

    struct lt_conn_handler_s *next;
} lt_conn_handler_t;

typedef struct connection_s {
    // libev tools
    struct ev_loop *loop;
    ev_io watcher;
    ev_idle idle;

    // status
    int fd;

    bool established;
    bool closed;
    bool destroying;

    bool pause_reading;

    int lasterr;

    // handler
    lt_conn_handler_t *handler;

    writing_task_t *writing_task;
    writing_task_t *writing_task_last;

    // settings
    bool auto_destroy;
} lt_conn_t;

void lt_conn_io_cb(EV_P_ ev_io *w, int revents);
void lt_conn_destroy(lt_conn_t *conn);

void _lt_conn_restart_ev(lt_conn_t *conn) {
    if (conn->closed) {
        return;
    }

    if (ev_is_active(&conn->watcher)) {
        ev_io_stop(conn->loop, &conn->watcher);
    }
    int events = 0;
    if (!conn->pause_reading) {
        events |= EV_READ;
    }
    if (conn->writing_task || !conn->established) {
        events |= EV_WRITE;
    }
    ev_io_set(&conn->watcher, conn->fd, events);
    ev_io_start(conn->loop, &conn->watcher);
}

lt_conn_t *
lt_create_conn(struct ev_loop *loop, const char *host, int port) {
    lt_conn_t *conn = NULL;

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;  // auto between ipv4 and ipv6
    hints.ai_socktype = SOCK_STREAM;  // tcp
    hints.ai_flags = AI_ADDRCONFIG;  // only returns supported ip version

    // 8 bytes enough for 65536
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        log_err("getaddrinfo failed");
        goto error;
    }

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            continue;
        }
        
        // set non-blocking io 
        if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
            log_err("fcntl failed");
            goto error;
        }

        // set keepalive
        int keepalive = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
                   sizeof(keepalive)) < 0) {
            log_err("setsockopt failed");
            goto error;
        }

        if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
            if (errno != EINPROGRESS) {
                log_err("connect failed, %d", errno);
                goto error;
            }
        }
    }

    conn = lt_alloc(lt_conn_t);

    conn->loop = loop;
    conn->fd = fd;

    ev_io_init(&conn->watcher, lt_conn_io_cb, conn->fd, EV_READ | EV_WRITE);
    conn->watcher.data = conn;

    _lt_conn_restart_ev(conn);

    freeaddrinfo(res);
    return conn;

error:
    if (fd >= 0) {
        close(fd);
    }
    if (res) {
        freeaddrinfo(res);
    }
    if (conn) {
        free(conn);
    }

    return NULL;
}

void _lt_conn_run_handler(lt_conn_t *conn, int event) {
    for (lt_conn_handler_t *h = conn->handler; h; h = h->next) {
        h->cb(conn, h->data, event);
    }
}

void lt_conn_close(lt_conn_t *conn) {
    if (conn->closed) {
        return;        
    }
    conn->closed = true;

    if (conn->established) {
        _lt_conn_run_handler(conn, LT_CONN_HUP);
    }

    _lt_conn_run_handler(conn, LT_CONN_CLOSE);
    ev_io_stop(conn->loop, &conn->watcher);
    close(conn->fd);

    if (conn->auto_destroy) {
        lt_conn_destroy(conn);
    }
}

void _lt_conn_destroy_cb(EV_P_ ev_idle *w, int revents) {
    lt_conn_t *conn = w->data;
    ev_idle_stop(conn->loop, w);

    while (conn->handler) {
        lt_conn_handler_t *h = conn->handler;
        conn->handler = h->next;
        free(h);
    }
    free(conn);
}

void lt_conn_destroy(lt_conn_t *conn) {
    if (conn->destroying) {
        return;
    }
    conn->destroying = true;

    lt_conn_close(conn);

    _lt_conn_run_handler(conn, LT_CONN_DESTROY);

    ev_idle_init(&conn->idle, _lt_conn_destroy_cb);
    conn->idle.data = conn;
    ev_idle_start(conn->loop, &conn->idle);
}

void lt_conn_io_cb(EV_P_ ev_io *w, int revents) {
    lt_conn_t *conn = w->data;

    if (!conn->established) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err == 0) {
            conn->established = 1;
            _lt_conn_run_handler(conn, LT_CONN_ESTABLISHED);
            _lt_conn_restart_ev(conn);
        } else {
            conn->lasterr = err;
            _lt_conn_run_handler(conn, LT_CONN_CONN_ERROR);
            lt_conn_close(conn);
            return;
        }
    }

    if (revents & EV_WRITE) {
        while (conn->writing_task) {
            writing_task_t *task = conn->writing_task;
            int nwrite = write(conn->fd, task->data + task->written,
                               task->len - task->written);
            if (nwrite < 0) {
                if (errno == EAGAIN) {
                    // writing buf full
                    break;
                } else {
                    log_err("write error: %d", errno);
                    return;
                }
            }

            task->written += nwrite;
            if (task->written == task->len) {
                if (task->freedata) {
                    free(task->data);
                }
                conn->writing_task = task->next;
                if (!conn->writing_task) {
                    conn->writing_task_last = NULL;
                }
                free(task);
            }
        }
        _lt_conn_run_handler(conn, LT_CONN_WRITE_AVIL);
    }

    if (revents & EV_READ) {
        int available_bytes = -1;
        if (ioctl(conn->fd, FIONREAD, &available_bytes) == -1) {
            log_err("ioctl failed: %d", errno);
            lt_conn_close(conn);
            return;
        }

        if (available_bytes == 0) {
            lt_conn_close(conn);
            return;
        } else {
            _lt_conn_run_handler(conn, LT_CONN_READ_AVIL);
        }
    }
}

void lt_conn_pause_read(lt_conn_t *conn, bool b) {
    if (conn->pause_reading == b) {
        return;
    }

    _lt_conn_restart_ev(conn);
}

bool lt_conn_write(lt_conn_t *conn, char *data, int len, bool freedata) {
    int nwrite = 0;

    if (!conn->writing_task) {
        nwrite = write(conn->fd, data, len);
        if (nwrite < 0) {
            if (errno == EAGAIN) {
                nwrite = 0;
            } else {
                goto error;
            }
        }
    }

    if (nwrite == len) {
        if (freedata) {
            free(data);
        }
        return true;
    }

    writing_task_t *task = lt_alloc(writing_task_t);
    task->data = data;
    task->len = len;
    task->written = nwrite;
    task->freedata = freedata;
    task->next = NULL;

    if (conn->writing_task_last) {
        conn->writing_task_last->next = task;
    } else {
        conn->writing_task = conn->writing_task_last = task;
    }

    return true;

error:
    if (freedata) {
        free(data);
    }
    return false;
}

void
lt_conn_add_handler(lt_conn_t *conn, lt_conn_callback cb, void *data) {
    lt_conn_handler_t *h = lt_alloc(lt_conn_handler_t);
    h->cb = cb;
    h->data = data;
    h->next = NULL;

    h->next = conn->handler;
    conn->handler = h;
}

void lt_conn_pipe_left_cb(lt_conn_t *left, void *data, int event) {
    lt_conn_t *right = data;

    if (event == LT_CONN_READ_AVIL) {
        int available_bytes = -1;
        if (ioctl(left->fd, FIONREAD, &available_bytes) == -1) {
            log_err("ioctl failed: %d", errno);
            lt_conn_close(left);
            lt_conn_close(right);
            return;
        }

        if (available_bytes > 0) {
            char *buf = lt_alloc_array(char, available_bytes);
            int nread = read(left->fd, buf, available_bytes);
            if (!lt_conn_write(right, buf, nread, true)) {
                log_err("lt_conn_write failed");
                lt_conn_close(left);
                lt_conn_close(right);
                return;
            }

            lt_conn_pause_read(left, right->writing_task ? true : false);
        }
    } else if (event == LT_CONN_CLOSE) {
        lt_conn_close(right);
    }
}

void lt_conn_pipe_right_cb(lt_conn_t *right, void *data, int event) {
    lt_conn_t *left = data;

    if (event == LT_CONN_WRITE_AVIL) {
        lt_conn_pause_read(left, false);
    } else if (event == LT_CONN_CLOSE) {
        lt_conn_close(left);
    }
}

void lt_conn_pipe_to(lt_conn_t *left, lt_conn_t *right) {
    lt_conn_add_handler(left, lt_conn_pipe_left_cb, right);
    lt_conn_add_handler(right, lt_conn_pipe_right_cb, left);
}

////////////////////////////////////////////////////////////////////////////////
// localtunnel

#define MAX_CONSECUTIVE_ERRORS 3
#define MIN_CONNS              3
#define MIN_IDLE_CONNS         1
#define DEFAULT_MAX_CONN       4

typedef struct {
    struct ev_loop *loop;

    // config
    char *host;

    char *local_host;
    int local_port;

    // options from server
    char *remote_host;
    int remote_port;

    char *id;
    char *url;
    char *cached_url;
    int max_conn_count;

    // running status
    int conn_connecting;
    int conn_idle;
    int conn_in_use;
    int consecutive_errors;
} localtunnel_t;

typedef struct {
    localtunnel_t *lt;
    lt_conn_t *remote;
    lt_conn_t *local;
} localtunnel_conn_t;

localtunnel_conn_t *localtunnel_create_conn(localtunnel_t *lt);

void cleanup_localtunnel(localtunnel_t *lt) {
    free(lt->host);
    free(lt->local_host);
    free(lt->remote_host);
    free(lt->id);
    free(lt->url);
    free(lt->cached_url);
}

bool parse_localtunnel_response(const char *resp, int len, localtunnel_t *lt) {
    bool br = false;

    cJSON *json = cJSON_ParseWithLength(resp, len);
    if (!json) {
        log_err("failed to parse response: %.*s", len, resp);
        goto cleanup;
    }

    cJSON *id = cJSON_GetObjectItem(json, "id");
    cJSON *ip = cJSON_GetObjectItem(json, "ip");
    cJSON *port = cJSON_GetObjectItem(json, "port");
    cJSON *max_conn_count = cJSON_GetObjectItem(json, "max_conn_count");
    cJSON *url = cJSON_GetObjectItem(json, "url");
    cJSON *cached_url = cJSON_GetObjectItem(json, "cached_url");

    if (!lt->id && id && id->type == cJSON_String) {
        lt->id = lt_strdup(id->valuestring);
    }

    if (ip && ip->type == cJSON_String) {
        lt->remote_host = lt_strdup(ip->valuestring);
    } else {
        lt->remote_host = lt_strdup(lt->host);
    }

    if (port && port->type == cJSON_Number) {
        lt->remote_port = port->valueint;
    } else {
        log_err("no port in response");
        goto cleanup;
    }

    if (max_conn_count && max_conn_count->type == cJSON_Number) {
        lt->max_conn_count = max_conn_count->valueint;
    } else {
        lt->max_conn_count = DEFAULT_MAX_CONN;
    }

    if (url && url->type == cJSON_String) {
        lt->url = lt_strdup(url->valuestring);
    } else {
        log_err("no url in response");
        goto cleanup;
    }

    if (cached_url && cached_url->type == cJSON_String) {
        lt->cached_url = lt_strdup(cached_url->valuestring);
    }

    br = true;

cleanup:
    cJSON_Delete(json);
    return true;
}

bool request_localtunnel(localtunnel_t *lt) {
    CURL *curl = NULL;
    bool br = false;
    char url[1024];
    lt_buf_t resp = {0};

    if (lt->id) {
        snprintf(url, sizeof(url), "https://%s/%s", lt->host, lt->id);
    } else {
        snprintf(url, sizeof(url), "https://%s/?new", lt->host);
    }

    curl = curl_easy_init();
    if (!curl) {
        log_err("curl_easy_init failed");
        goto cleanup;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ls_buf_write);

    log("requesting localtunel");
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_err("curl_easy_perform failed: %s", curl_easy_strerror(res));
        goto cleanup;
    }
    log("localtunnel response: %.*s", (int)resp.size, resp.buf);

    br = parse_localtunnel_response(resp.buf, resp.size, lt);
    if (br) {
        printf("Your URL is: %s\n", lt->url);
        if (lt->cached_url) {
            printf("Your cached URL is: %s\n", lt->cached_url);
        }
    } else {
        log_err("failed to parse response");
    }

cleanup:
    cleanup_buf(&resp);
    if (curl) {
        curl_easy_cleanup(curl);
    }
    return br;
}

void localtunnel_local_cb(lt_conn_t *conn, void *data, int event) {
    localtunnel_conn_t *ltc = data;
    localtunnel_t *lt = ltc->lt;
    if (event == LT_CONN_CONN_ERROR) {
        log_err("*%d failed to connect to %s %d, error: %s",
            conn->fd, lt->local_host, lt->local_port, strerror(conn->lasterr));
    } else if (event == LT_CONN_DESTROY) {
        ltc->local = NULL;
        if (!ltc->remote && !ltc->local) {
            free(ltc);
        }
    }
}

void localtunnel_try_create_more_connection(localtunnel_t *lt) {
    int total_conns = lt->conn_connecting + lt->conn_idle + lt->conn_in_use;
    if (total_conns < lt->max_conn_count) {
        if (total_conns < MIN_CONNS || lt->conn_idle < MIN_IDLE_CONNS) {
            // create more connections
            localtunnel_create_conn(lt);
        }
    }
}

void localtunnel_cb(lt_conn_t *conn, void *data, int event) {
    localtunnel_conn_t *ltc = data;
    localtunnel_t *lt = ltc->lt;

    if (event == LT_CONN_ESTABLISHED) {
        log("*%d established", conn->fd);

        lt->conn_connecting -= 1;
        lt->conn_idle += 1;
        lt->consecutive_errors = 0;

        localtunnel_try_create_more_connection(lt);
    } else if (event == LT_CONN_CONN_ERROR) {
        log_err("*%d failed to connect to %s %d, error: %s",
            conn->fd, lt->remote_host, lt->remote_port,
            strerror(conn->lasterr));
        
        lt->conn_connecting -= 1;
        lt->consecutive_errors += 1;
        if (lt->consecutive_errors >= MAX_CONSECUTIVE_ERRORS) {
            log_err("max consecutive errors reached, exit");
            exit(1);
        } else {
            // retry
            localtunnel_create_conn(lt);
        }
    } else if (event == LT_CONN_READ_AVIL) {
        if (!ltc->local) {
            ltc->local = lt_create_conn(
                conn->loop, lt->local_host, lt->local_port);
            if (!ltc->local) {
                log_err("failed to create local connection");
                lt_conn_close(conn);
                return;
            }
            ltc->local->auto_destroy = true;
            lt_conn_add_handler(ltc->local, localtunnel_local_cb, ltc);
            lt_conn_pipe_to(ltc->remote, ltc->local);
            lt_conn_pipe_to(ltc->local, ltc->remote);

            log("*%d bridged: %d<=>%d",
                ltc->remote->fd, ltc->remote->fd, ltc->local->fd);
            
            lt->conn_idle -= 1;
            lt->conn_in_use += 1;
            localtunnel_try_create_more_connection(lt);
        }
    } else if (event == LT_CONN_HUP) {
        if (ltc->local) {
            log("*%d<=>%d closed", ltc->remote->fd, ltc->local->fd);
            lt->conn_in_use -= 1;
        } else {
            log("*%d closed", ltc->remote->fd);
            lt->conn_idle -= 1;
        }
        localtunnel_try_create_more_connection(lt);
    } else if (event == LT_CONN_DESTROY) {
        ltc->remote = NULL;
        if (!ltc->remote && !ltc->local) {
            free(ltc);
        }
    }
}

localtunnel_conn_t *localtunnel_create_conn(localtunnel_t *lt) {
    localtunnel_conn_t *ltc = lt_alloc(localtunnel_conn_t);

    ltc->lt = lt;
    ltc->remote = lt_create_conn(lt->loop, lt->remote_host, lt->remote_port);
    if (!ltc->remote) {
        log_err("failed to create connection");
        free(ltc);
        return NULL;
    }
    ltc->remote->auto_destroy = true;
    lt_conn_add_handler(ltc->remote, localtunnel_cb, ltc);

    lt->conn_connecting += 1;
    log("*%d initialized to %s %d",
        ltc->remote->fd, lt->remote_host, lt->remote_port);

    return ltc;
}

////////////////////////////////////////////////////////////////////////////////
// main

int localtunnel_main(localtunnel_t *lt) {
    if (!request_localtunnel(lt)) {
        log_err("failed to request localtunnel");
        return 1;
    }

    if (!localtunnel_create_conn(lt)) {
        log_err("failed to initialize connection");
        return 1;
    }

    return ev_run(lt->loop, 0);
}

void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s -p port [other options]\n", argv0);
    fprintf(stderr, "  -l, --local <host>           local host, default: localhost\n");
    fprintf(stderr, "  -p, --port <port>            local port, default: 8000\n");
    fprintf(stderr, "  -h, --host <host>            remote server, default: localtunnel.me\n");
    fprintf(stderr, "  -s, --subdomain <subdomain>  subdomain, default: random\n");
    fprintf(stderr, "  -v, --verbose                verbose mode\n");
    fprintf(stderr, "      --help                   print this\n");
}

int main(int argc, char *argv[]) {
    localtunnel_t lt = {0};
    lt.loop = EV_DEFAULT;

    struct option long_options[] = {
        {"local", required_argument, 0, 'l'},
        {"port", required_argument, 0, 'p'},
        {"host", required_argument, 0, 'h'},
        {"subdomain", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 0},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "l:p:h:s:v", long_options, NULL)) != -1) {
        switch (opt) {
        case 'l':
            lt.local_host = lt_strdup(optarg);
            break;
        case 'p':
            lt.local_port = atoi(optarg);
            break;
        case 'h':
            lt.host = lt_strdup(optarg);
            break;
        case 's':
            lt.id = lt_strdup(optarg);
            break;
        case 'v':
            _enable_log = true;
            break;
        case 0:
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }

    if (!lt.local_port) {
        lt.local_port = 8000;
    }
    if (!lt.host) {
        lt.host = lt_strdup("localtunnel.me");
    }
    if (!lt.local_host) {
        lt.local_host = lt_strdup("localhost");
    }

    curl_global_init(CURL_GLOBAL_ALL);
    int exit_code = localtunnel_main(&lt);

cleanup:
    cleanup_localtunnel(&lt);
    curl_global_cleanup();
    return exit_code;
}
