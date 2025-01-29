/*
 * Copyright (C) Chizhong Jin
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <curl/curl.h>
#include <cjson/cJSON.h>

////////////////////////////////////////////////////////////////////////////////
// dyn_buf_t

typedef struct {
    size_t size;
    size_t cap;
    char *buf;
} dyn_buf_t;

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
            perror("malloc");
            return 0;
        }
        buf->cap = new_cap;
    }
    memcpy(buf->buf + buf->size, data, size * nmemb);
    buf->size = new_size;
    return size * nmemb;
}

////////////////////////////////////////////////////////////////////////////////
// tunnel

typedef struct {
    char *id;
    int port;
    int max_conn_count;
    char *url;
} tunnel_ctx_t;

void cleanup_tunnel_ctx(tunnel_ctx_t *ctx) {
    free(ctx->id);
    free(ctx->url);
}

void dump_tunnel_ctx(tunnel_ctx_t *ctx) {
    printf("id: %s\n", ctx->id);
    printf("port: %d\n", ctx->port);
    printf("max_conn_count: %d\n", ctx->max_conn_count);
    printf("url: %s\n", ctx->url);
}

bool parse_localtunnel_response(const char *resp, int len, tunnel_ctx_t *ctx) {
    cJSON *json = cJSON_ParseWithLength(resp, len);
    if (!json) {
        perror("cJSON_Parse");
        return false;
    }

    cJSON *id = cJSON_GetObjectItem(json, "id");
    cJSON *port = cJSON_GetObjectItem(json, "port");
    cJSON *max_conn_count = cJSON_GetObjectItem(json, "max_conn_count");
    cJSON *url = cJSON_GetObjectItem(json, "url");

    if (id && id->type == cJSON_String) {
        ctx->id = strdup(id->valuestring);
    }

    if (port && port->type == cJSON_Number) {
        ctx->port = id->valueint;
    } else {
        perror("aaa");
        return false;
    }

    if (max_conn_count && max_conn_count->type == cJSON_Number) {
        ctx->max_conn_count = max_conn_count->valueint;
    } else {
        ctx->max_conn_count = 4;
    }

    if (url && url->type == cJSON_String) {
        ctx->url = strdup(url->valuestring);
    } else {
        perror("aaa");
        return false;
    }

    return true;
}

bool request_localtunnel(tunnel_ctx_t *ctx) {
    CURL *curl;
    CURLcode res;
    bool br;

    curl = curl_easy_init();
    if (!curl) {
        perror("curl_easy_init");
        return 1;
    }

    dyn_buf_t resp = {0};

    curl_easy_setopt(curl, CURLOPT_URL, "https://localtunnel.me/?new");
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dyn_buf_write);


    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        return false;
    }

    br = parse_localtunnel_response(resp.buf, resp.size, ctx);

    curl_easy_cleanup(curl);
    return br;
}

int main(int argc, char *argv[]) {
    curl_global_init(CURL_GLOBAL_ALL);

    tunnel_ctx_t ctx = {0};
    request_localtunnel(&ctx);
    dump_tunnel_ctx(&ctx);
    cleanup_tunnel_ctx(&ctx);

    curl_global_cleanup();
    return 0;
}
