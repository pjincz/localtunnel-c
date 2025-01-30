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
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <curl/curl.h>
#include <cjson/cJSON.h>

////////////////////////////////////////////////////////////////////////////////
// log

#define log(format, ...) do { \
    time_t t = time(NULL); \
    struct tm *tm_info = localtime(&t); \
    char time_buf[20]; \
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info); \
    fprintf(stderr, "%s " format "\n", time_buf, ##__VA_ARGS__); \
} while (0)

////////////////////////////////////////////////////////////////////////////////
// dyn_buf_t

typedef struct {
    size_t size;
    size_t cap;
    char *buf;
} dyn_buf_t;

void cleanup_buf(dyn_buf_t *buf) {
    free(buf->buf);
}

size_t
dyn_buf_write(const void *data, size_t size, size_t nmemb, dyn_buf_t *buf) {
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
// framework

typedef struct connection_s {
    struct event_loop_s *ev;

    int fd;

    // read handler, will be invoked when data arrives
    // if closing is set, it means not a normal read event, it's the last call
    // of reader.
    // if you don't want to read anything from connection, you can do
    // connection_close_read() immediently after create connection.
    void (*reader)(struct connection_s*, void *data, bool closing);

    // write hander, will be invoked when writing buffer is available
    // if closing is set, it means not a normal write event, it's the last call
    // of writer.
    // if you don't want to write anything to connection, you can do
    // connection_close_write() immediently after create connection.
    void (*writer)(struct connection_s*, void *data, bool closing);

    // user data
    void *reader_data;
    void *writer_data;

    // chain
    struct connection_s *prev, *next;

    bool read_closed;
    bool write_closed;
    bool pending_read;
    bool pending_write;
} connection_t;

typedef struct event_loop_s {
    connection_t *first, *last;
    bool closing;

    int slots;
    struct pollfd *pfds;
    connection_t **slot_map;
} event_loop_t;

connection_t *
create_connection(event_loop_t *ev, const char *host, int port) {
    if (ev->closing) {
        log("failed to create connection, ev is closing");
        return NULL;
    }

    connection_t *conn = NULL;

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

    int fd;
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

    conn->ev = ev;
    conn->fd = fd;
    conn->reader = NULL;
    conn->writer = NULL;
    conn->reader_data = NULL;
    conn->writer_data = NULL;

    conn->next = NULL;
    conn->prev = ev->last;
    if (ev->last) {
        ev->last->next = conn;
    }
    ev->last = conn;
    if (!ev->first) {
        ev->first = conn;
    }

    conn->read_closed = false;
    conn->write_closed = false;
    conn->pending_read = true;
    conn->pending_write = true;

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

void
_free_connection(connection_t *conn) {
    event_loop_t *ev = conn->ev;
    connection_t *prev = conn->prev;
    connection_t *next = conn->next;

    if (prev) {
        prev->next = next;
    } else {
        ev->first = next;
    }

    if (next) {
        next->prev = prev;
    } else {
        ev->last = prev;
    }

    close(conn->fd);
    free(conn);
}

void
connection_close_read(connection_t *c) {
    if (c->read_closed) {
        log("connection read already closed");
        return;
    }

    shutdown(c->fd, SHUT_RD);

    if (c->reader) {
        c->reader(c, c->reader_data, true);
    }

    c->read_closed = true;
    c->pending_read = false;

    if (c->read_closed && c->write_closed) {
        _free_connection(c);
    }
}

void
connection_close_write(connection_t *c) {
    if (c->write_closed) {
        log("connection write already closed");
        return;
    }

    shutdown(c->fd, SHUT_WR);

    if (c->writer) {
        c->writer(c, c->writer_data, true);
    }

    c->write_closed = true;
    c->pending_write = false;

    if (c->read_closed && c->write_closed) {
        _free_connection(c);
    }
}

void
connection_pending_read(connection_t *c, bool v) {
    if (v && c->read_closed) {
        log("connection read already closed");
        return;
    }
    c->pending_read = v;
}

void
connection_pending_write(connection_t *c, bool v) {
    if (v && c->write_closed) {
        log("connection write already closed");
        return;
    }
    c->pending_write = v;
}

event_loop_t *
create_event_loop() {
    event_loop_t *ev;
    ev = malloc(sizeof(*ev));
    if (!ev) {
        return NULL;
    }
    memset(ev, 0, sizeof(*ev));
    return ev;
}

void
free_event_loop(event_loop_t *ev) {
    ev->closing = true;

    while (ev->first) {
        connection_t *c = ev->first;
        if (!c->read_closed) {
            connection_close_read(c);
        }
        if (!c->write_closed) {
            connection_close_write(c);
        }
    }

    free(ev->pfds);
    free(ev->slot_map);
    free(ev);
}

// returns:
//   <0: error
//   0: nothing need to do anymore
//   >0: good
int do_poll(event_loop_t *ev) {
    int slot = 0;
    for (connection_t *c = ev->first; c; c = c->next, slot += 1) {
        if (slot >= ev->slots) {
            int new_slots = ev->slots ? ev->slots * 2 : 16;
            struct pollfd *new_pfds = realloc(
                ev->pfds, sizeof(struct pollfd) * new_slots);
            if (!new_pfds) {
                log("realloc error");
                return -1;
            }
            ev->pfds = new_pfds;

            connection_t **new_slot_map = realloc(
                ev->slot_map, sizeof(connection_t*) * new_slots);
            if (!new_slot_map) {
                log("realloc error");
                return -1;
            }        
            ev->slot_map = new_slot_map;

            ev->slots = new_slots;
        }

        ev->pfds[slot].fd = c->fd;
        ev->pfds[slot].events = POLLHUP | POLLERR;
        if (c->pending_read) {
            if (!c->reader) {
                log("connectin pending read, but no reader");
                log("If you don't want to read anything, you can invoke "
                    "connection_close_read() immediently after creating "
                    "connection.");
                return -1;
            }
            ev->pfds[slot].events |= POLLIN;
            // log("*%d wait reading", c->fd);
        }
        if (c->pending_write) {
            if (!c->writer) {
                log("connectin pending write, but no writer");
                log("If you don't want to write anything, you can invoke "
                    "connection_close_write() immediently after creating "
                    "connection.");
                return -1;
            }
            ev->pfds[slot].events |= POLLOUT;
            // log("*%d wait writing", c->fd);
        }
        ev->slot_map[slot] = c;
    }
    int nslot = slot;

    if (nslot == 0) {
        return 0;
    }

    int ir = poll(ev->pfds, slot, -1);
    if (ir < 0) {
        log("poll error");
        return ir;
    }

    for (int i = 0; i < nslot; ++i) {
        short revents = ev->pfds[i].revents;
        connection_t *c = ev->slot_map[i];

        // It looks there's an known issue on Linux poll, sometimes even remote
        // socket closed, even there's no data remain, Linux still keep set
        // POLLIN instead of POLLHUP. Let's do a workaround here.
        if (revents & POLLIN) {
            int bytes_available = 0;
            if (ioctl(c->fd, FIONREAD, &bytes_available) >= 0) {
                if (bytes_available == 0) {
                    revents = revents & ~POLLIN | POLLHUP;
                }
            }
        }

        if (revents & POLLIN) {
            assert(c->reader);
            c->reader(c, c->reader_data, false);
        }
        if (revents & POLLOUT) {
            assert(c->writer);
            c->writer(c, c->writer_data, false);
        }
        if (revents & (POLLHUP | POLLERR | POLLNVAL)) {
            if (!c->read_closed) {
                connection_close_read(c);
            }
            if (!c->write_closed) {
                connection_close_write(c);
            }
        }
    }
    return 1;
}

////////////////////////////////////////////////////////////////////////////////
// pipe

#define PIPE_BUF_SIZE (16*1024)

typedef struct pipe_s {
    connection_t *left;
    connection_t *right;

    bool left_closed;
    bool right_closed;

    void(*cleanup)(struct pipe_s*);
    void *data;

    char *mem;
    char *mem_end;
    char *buf;
    char *buf_end;
} pipe_t;

void free_pipe(pipe_t *p) {
    if (p->cleanup) {
        p->cleanup(p);
    }
    free(p->mem);
    free(p);
}

void pipe_writer(connection_t *c, void *data, bool closing) {
    pipe_t *p = data;

    if (closing) {
        p->right_closed = true;
        if (p->left_closed) {
            free_pipe(p);
        } else {
            connection_close_read(p->left);
        }
        return;
    }

    if (p->buf_end == p->buf) {
        // nothing to write
        connection_pending_write(p->right, false);
        return;
    }

    int nwrite = write(p->right->fd, p->buf, p->buf_end - p->buf);
    if (nwrite < 0) {
        log("write error");
        return;
    } else if (nwrite > 0) {
        p->buf += nwrite;
        if (p->buf == p->buf_end) {
            p->buf = p->buf_end = p->mem;
        }
        connection_pending_read(p->left, p->buf_end != p->mem_end);
        connection_pending_write(p->right, p->buf_end != p->buf);
    }
}

void pipe_reader(connection_t *c, void *data, bool closing) {
    pipe_t *p = data;

    if (closing) {
        p->left_closed = true;
        if (p->right_closed) {
            free_pipe(p);
        } else {
            if (p->buf == p->buf_end) {
                connection_close_write(p->right);
            }
        }
        return;
    }

    int nrem = p->mem_end - p->buf_end;
    int nread = read(p->left->fd, p->buf_end, nrem);
    if (nread < 0) {
        log("read error");
        return;
    } else if (nread > 0) {
        p->buf_end += nread;
        pipe_writer(p->right, p->right->writer_data, 0);
    }
}

pipe_t *
pipe_connections(connection_t *left, connection_t *right) {
    if (left->read_closed) {
        log("left connection already closed read");
        return NULL;
    }
    if (right->write_closed) {
        log("right connection already closed write");
        return NULL;
    }

    pipe_t *p = malloc(sizeof(*p));
    if (!p) {
        log("malloc error");
        return NULL;
    }
    p->left = left;
    p->right = right;

    p->left_closed = false;
    p->right_closed = false;

    p->cleanup = NULL;
    p->data = NULL;

    p->mem = malloc(PIPE_BUF_SIZE);
    if (!p->mem) {
        log("malloc error");
        free(p);
        return NULL;
    }
    p->mem_end = p->mem + PIPE_BUF_SIZE;

    p->buf = p->buf_end = p->mem;

    left->reader = pipe_reader;
    left->reader_data = p;
    right->writer = pipe_writer;
    right->writer_data = p;

    return p;
}

////////////////////////////////////////////////////////////////////////////////
// localtunnel

typedef struct {
    char *id;
    char *host;
    int port;
    int max_conn_count;
    char *url;

    event_loop_t *ev;
    int conns;
} localtunnel_t;

void localtunnel_remote_reader(connection_t *c, void *data, bool closing);
void localtunnel_remote_writer(connection_t *c, void *data, bool closing);

void cleanup_localtunnel(localtunnel_t *lt) {
    if (lt->ev) {
        free_event_loop(lt->ev);
    }

    free(lt->id);
    free(lt->host);
    free(lt->url);
}

void dump_tunneltunnel(localtunnel_t *lt) {
    printf("id: %s\n", lt->id ? lt->id : "");
    printf("host: %s\n", lt->host ? lt->host : "");
    printf("port: %d\n", lt->port);
    printf("max_conn_count: %d\n", lt->max_conn_count);
    printf("url: %s\n", lt->url ? lt->url : "");
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
        lt->port = port->valueint;
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
    dyn_buf_t resp = {0};

    if (!lt->host) {
        lt->host = strdup("localtunnel.me");
        if (!lt->host) {
            log("strdup failed");
            goto cleanup;
        }
    }

    snprintf(url, sizeof(url), "https://%s/?new", lt->host);

    curl = curl_easy_init();
    if (!curl) {
        log("curl_easy_init failed");
        goto cleanup;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dyn_buf_write);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log("curl_easy_perform failed: %s", curl_easy_strerror(res));
        goto cleanup;
    }

    br = parse_localtunnel_response(resp.buf, resp.size, lt);

cleanup:
    cleanup_buf(&resp);
    if (curl) {
        curl_easy_cleanup(curl);
    }
    return br;
}

connection_t *
create_localtunnel_connection(localtunnel_t *lt) {
    connection_t *remote = create_connection(lt->ev, lt->host, lt->port);
    if (!remote) {
        log("failed to create localtunnel connection");
        return NULL;
    }

    remote->reader = localtunnel_remote_reader;
    remote->reader_data = lt;
    remote->writer = localtunnel_remote_writer;
    remote->writer_data = lt;
    lt->conns += 1;
}

void localtunnel_pipe_cleanup(pipe_t *p) {
    localtunnel_t *lt = p->data;
    log("connection %d <=> %d closed", p->left->fd, p->right->fd);

    // create a new one, when one exits
    if (!lt->ev->closing) {
        create_localtunnel_connection(lt);
    }
    // TODO: if failed, delay retry
}

void localtunnel_remote_reader(connection_t *c, void *data, bool closing) {
    localtunnel_t *lt = data;

    if (closing) {
        log("connection %d closed", c->fd);

        // create a new one, when one exits
        if (!lt->ev->closing) {
            create_localtunnel_connection(lt);
        }
        // TODO: if failed, delay retry

        return;
    }

    connection_t *local = create_connection(c->ev, "127.0.0.1", 80);
    if (!local) {
        log("failed to create local connection");
        connection_close_read(c);
        connection_close_write(c);
        return;
    }
    
    pipe_t *forward = pipe_connections(c, local);
    pipe_t *backward = pipe_connections(local, c);
    if (!forward || !backward) {
        log("failed to bridge %d <=> %d", c->fd, local->fd);
        connection_close_read(c);
        connection_close_write(c);
        return;
    }

    // only set cleanup on one direction
    forward->cleanup = localtunnel_pipe_cleanup;
    forward->data = lt;

    log("connection bridged %d <=> %d", c->fd, local->fd);
}

void localtunnel_remote_writer(connection_t *c, void *data, bool closing) {
    localtunnel_t *lt = data;

    if (closing) {
        return;
    }

    log("connection %d established", c->fd);
    connection_pending_write(c, false);
}

////////////////////////////////////////////////////////////////////////////////
// main

int main(int argc, char *argv[]) {
    curl_global_init(CURL_GLOBAL_ALL);

    localtunnel_t lt = {0};
    if (!request_localtunnel(&lt)) {
        log("failed to request localtunnel");
        return 1;
    }
    dump_tunneltunnel(&lt);

    lt.ev = create_event_loop();
    if (!lt.ev) {
        log("failed to create event loop");
        return 1;
    }

    create_localtunnel_connection(&lt);

    while (true) {
        int ir = do_poll(lt.ev);
        if (ir < 0) {
            return 1;
        } else if (ir == 0) {
            break;
        }
    }

    cleanup_localtunnel(&lt);
    curl_global_cleanup();
    return 0;
}
