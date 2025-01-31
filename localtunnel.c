/*
 * Copyright (C) Chizhong Jin
 */


#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

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

#define log(format, ...) do { \
    time_t t = time(NULL); \
    struct tm *tm_info = localtime(&t); \
    char time_buf[20]; \
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info); \
    fprintf(stderr, "%s] " format "\n", time_buf, ##__VA_ARGS__); \
} while (0)

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
ls_buf_write(const void *data, size_t size, size_t nmemb, lt_buf_t *buf) {
    size_t new_size = buf->size + size * nmemb;
    if (new_size > buf->cap) {
        size_t new_cap = buf->cap ? buf->cap : new_size;
        while (new_cap < new_size) {
            new_cap *= 2;
        }
        buf->buf = realloc(buf->buf, new_cap);
        if (!buf->buf) {
            log("realloc failed");
            return 0;
        }
        buf->cap = new_cap;
    }
    memcpy(buf->buf + buf->size, data, size * nmemb);
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
        log("getaddrinfo failed");
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
            log("fcntl failed");
            goto error;
        }

        // set keepalive
        int keepalive = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
                   sizeof(keepalive)) < 0) {
            log("setsockopt failed");
            goto error;
        }

        if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
            if (errno != EINPROGRESS) {
                log("connect failed, %d", errno);
                goto error;
            }
        }
    }

    conn = malloc(sizeof(*conn));
    if (!conn) {
        log("malloc error");
        goto error;
    }
    memset(conn, 0, sizeof(*conn));

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
    // log("revents = %x", revents);

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
                    log("write error: %d", errno);
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
            log("ioctl failed: %d", errno);
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

    writing_task_t *task = malloc(sizeof(*task));
    if (!task) {
        goto error;
    }
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

lt_conn_handler_t * 
lt_conn_add_handler(lt_conn_t *conn, lt_conn_callback cb, void *data) {
    lt_conn_handler_t *h = malloc(sizeof(*h));
    if (!h) {
        log("malloc failed");
        return NULL;
    }
    h->cb = cb;
    h->data = data;
    h->next = NULL;

    h->next = conn->handler;
    conn->handler = h;

    return h;
}

void lt_conn_pipe_left_cb(lt_conn_t *left, void *data, int event) {
    lt_conn_t *right = data;

    if (event == LT_CONN_READ_AVIL) {
        int available_bytes = -1;
        if (ioctl(left->fd, FIONREAD, &available_bytes) == -1) {
            log("ioctl failed: %d", errno);
            lt_conn_close(left);
            lt_conn_close(right);
            return;
        }

        if (available_bytes > 0) {
            char *buf = malloc(available_bytes);
            if (!buf) {
                log("malloc failed");
                lt_conn_close(left);
                lt_conn_close(right);
                return;
            }
            int nread = read(left->fd, buf, available_bytes);
            if (!lt_conn_write(right, buf, nread, true)) {
                log("lt_conn_write failed");
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

bool lt_conn_pipe_to(lt_conn_t *left, lt_conn_t *right) {
    if (!lt_conn_add_handler(left, lt_conn_pipe_left_cb, right)) {
        log("lt_conn_add_handler failed");
        return false;
    }
    if (!lt_conn_add_handler(right, lt_conn_pipe_right_cb, left)) {
        log("lt_conn_add_handler failed");
        return false;
    }
    return true;
}

////////////////////////////////////////////////////////////////////////////////
// localtunnel

#define MAX_CONSECUTIVE_ERRORS 3
#define MIN_CONNS              4
#define MIN_IDLE_CONNS         1

typedef struct {
    struct ev_loop *loop;

    char *remote_host;
    int remote_port;

    char *local_host;
    int local_port;

    char *id;
    char *url;
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
    free(lt->remote_host);
    free(lt->local_host);
    free(lt->id);
    free(lt->url);
}

bool parse_localtunnel_response(const char *resp, int len, localtunnel_t *lt) {
    bool br = false;

    cJSON *json = cJSON_ParseWithLength(resp, len);
    if (!json) {
        log("bad response");
        goto cleanup;
    }

    cJSON *id = cJSON_GetObjectItem(json, "id");
    cJSON *port = cJSON_GetObjectItem(json, "port");
    cJSON *max_conn_count = cJSON_GetObjectItem(json, "max_conn_count");
    cJSON *url = cJSON_GetObjectItem(json, "url");

    if (id && id->type == cJSON_String) {
        lt->id = strdup(id->valuestring);
    }

    if (port && port->type == cJSON_Number) {
        lt->remote_port = port->valueint;
    } else {
        log("no port in response");
        goto cleanup;
    }

    if (max_conn_count && max_conn_count->type == cJSON_Number) {
        lt->max_conn_count = max_conn_count->valueint;
    } else {
        lt->max_conn_count = 4;
    }

    if (url && url->type == cJSON_String) {
        lt->url = strdup(url->valuestring);
    } else {
        log("no url in response");
        goto cleanup;
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

    if (!lt->remote_host) {
        lt->remote_host = strdup("localtunnel.me");
        if (!lt->remote_host) {
            log("strdup failed");
            goto cleanup;
        }
    }

    snprintf(url, sizeof(url), "https://%s/?new", lt->remote_host);

    curl = curl_easy_init();
    if (!curl) {
        log("curl_easy_init failed");
        goto cleanup;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ls_buf_write);

    log("requesting localtunel");
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log("curl_easy_perform failed: %s", curl_easy_strerror(res));
        goto cleanup;
    }
    log("localtunnel response: %.*s", (int)resp.size, resp.buf);

    br = parse_localtunnel_response(resp.buf, resp.size, lt);
    if (br) {
        printf("url: %s\n", lt->url);
    } else {
        log("failed to parse response");
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
        log("*%d failed to connect to %s %d, error: %s",
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
        log("*%d failed to connect to %s %d, error: %s",
            conn->fd, lt->remote_host, lt->remote_port,
            strerror(conn->lasterr));
        
        lt->conn_connecting -= 1;
        lt->consecutive_errors += 1;
        if (lt->consecutive_errors >= MAX_CONSECUTIVE_ERRORS) {
            log("max consecutive errors reached, exit");
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
                log("failed to create local connection");
                lt_conn_close(conn);
                return;
            }
            ltc->local->auto_destroy = true;
            if (!lt_conn_add_handler(ltc->local, localtunnel_local_cb, ltc)) {
                log("lt_conn_add_handler failed");
                lt_conn_close(ltc->local);
                lt_conn_close(ltc->remote);
                return;
            }
            if (!lt_conn_pipe_to(ltc->remote, ltc->local)
                || !lt_conn_pipe_to(ltc->local, ltc->remote))
            {
                log("failed to bridge connections");
                lt_conn_close(ltc->local);
                lt_conn_close(ltc->remote);
                return;
            }
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
    localtunnel_conn_t *ltc = malloc(sizeof(*ltc));
    if (!ltc) {
        log("malloc failed");
        return NULL;
    }
    memset(ltc, 0, sizeof(*ltc));

    ltc->lt = lt;
    ltc->remote = lt_create_conn(lt->loop, lt->remote_host, lt->remote_port);
    if (!ltc->remote) {
        log("failed to create connection");
        free(ltc);
        return NULL;
    }
    ltc->remote->auto_destroy = true;
    if (!lt_conn_add_handler(ltc->remote, localtunnel_cb, ltc)) {
        log("lt_conn_add_handler failed");
        lt_conn_close(ltc->remote);
        free(ltc);
        return NULL;
    }

    lt->conn_connecting += 1;
    log("*%d initialized to %s %d",
        ltc->remote->fd, lt->remote_host, lt->remote_port);

    return ltc;
}

////////////////////////////////////////////////////////////////////////////////
// main

void dump_conn_cb(lt_conn_t *conn, void *data, int event) {
    if (event == LT_CONN_READ_AVIL) {
        char buf[8192];
        int nread = read(conn->fd, buf, sizeof(buf));
        if (nread < 0) {
            if (errno != EAGAIN) {
                log("read error: %d", errno);
            }
            return;
        } else if (nread > 0) {
            printf("%.*s", nread, buf);
        }
    }
}

int main(int argc, char *argv[]) {
    struct ev_loop *loop = EV_DEFAULT;

    curl_global_init(CURL_GLOBAL_ALL);

    // lt_conn_t * conn = lt_create_conn(loop, "baidu.com", 80);
    // conn->auto_destroy = true;
    // lt_conn_add_handler(conn, dump_conn_cb, NULL);

    // char req[] = "GET / HTTP/1.1\r\n"
    //              "Host: baidu.com\r\n"
    //              "User-Agent: curl/8.5.0\r\n"
    //              "Accept: */*\r\n"
    //              "Connection: close\r\n"
    //              "\r\n";
    // lt_conn_write(conn, req, sizeof(req), false);
    // ev_run(loop, 0);

    {
        localtunnel_t lt = {0};
        lt.loop = loop;
        lt.local_host = strdup("127.0.0.1");
        lt.local_port = 80;

        if (!request_localtunnel(&lt)) {
            log("failed to request localtunnel");
            cleanup_localtunnel(&lt);
            return 1;
        }

        localtunnel_create_conn(&lt);

        ev_run(loop, 0);

        cleanup_localtunnel(&lt);
    }

    curl_global_cleanup();
    return 0;
}
