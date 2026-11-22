#define _POSIX_C_SOURCE 200809L

#include "scanner.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void sanitize_banner(char *str) {
    for (size_t i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\r' || str[i] == '\n') {
            str[i] = ' ';
        } else if (!isprint((unsigned char)str[i])) {
            str[i] = '.';
        }
    }
}

/* Échappe les caractères spéciaux JSON (" et \) lors de l'écriture */
static void write_json_escaped(FILE *fp, const char *str) {
    fputc('"', fp);
    for (size_t i = 0; str[i] != '\0'; i++) {
        if (str[i] == '"' || str[i] == '\\') {
            fputc('\\', fp);
        }
        fputc(str[i], fp);
    }
    fputc('"', fp);
}

/* Comparateur pour trier les ports par ordre croissant dans le JSON */
static int compare_ports(const void *a, const void *b) {
    const port_result_t *pa = (const port_result_t *)a;
    const port_result_t *pb = (const port_result_t *)b;
    return pa->port - pb->port;
}

bool resolve_target(const char *hostname, scan_context_t *ctx) {
    struct addrinfo hints, *res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(hostname, NULL, &hints, &res);
    if (status != 0 || res == NULL) {
        fprintf(stderr, "[!] Erreur résolution DNS pour '%s' : %s\n",
                hostname, gai_strerror(status));
        return false;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    ctx->target_addr = ipv4->sin_addr;

    if (inet_ntop(AF_INET, &(ctx->target_addr), ctx->resolved_ip, INET_ADDRSTRLEN) == NULL) {
        freeaddrinfo(res);
        return false;
    }

    freeaddrinfo(res);
    return true;
}

void scan_single_port(const scan_context_t *ctx, int port, port_result_t *result) {
    memset(result, 0, sizeof(port_result_t));
    result->port = port;
    result->is_open = false;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return;
    }

    struct timeval tv;
    tv.tv_sec = ctx->timeout_ms / 1000;
    tv.tv_usec = (ctx->timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr = ctx->target_addr;
    server_addr.sin_port = htons((uint16_t)port);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
        result->is_open = true;

        struct servent *srv = getservbyport(htons((uint16_t)port), "tcp");
        if (srv != NULL && srv->s_name != NULL) {
            snprintf(result->service_name, sizeof(result->service_name), "%s", srv->s_name);
        } else {
            snprintf(result->service_name, sizeof(result->service_name), "unknown");
        }

        ssize_t bytes_read = recv(sockfd, result->banner, sizeof(result->banner) - 1, 0);

        if (bytes_read <= 0 && (port == 80 || port == 8080 || port == 8000)) {
            const char *http_probe = "HEAD / HTTP/1.0\r\n\r\n";
            send(sockfd, http_probe, strlen(http_probe), 0);
            bytes_read = recv(sockfd, result->banner, sizeof(result->banner) - 1, 0);
        }

        if (bytes_read > 0) {
            result->banner[bytes_read] = '\0';
            sanitize_banner(result->banner);
        }
    }

    close(sockfd);
}

void *worker_thread(void *arg) {
    scan_context_t *ctx = (scan_context_t *)arg;
    port_result_t result;

    while (1) {
        pthread_mutex_lock(&ctx->lock);
        int port = ctx->current_port++;
        pthread_mutex_unlock(&ctx->lock);

        if (port > ctx->end_port) {
            break;
        }

        scan_single_port(ctx, port, &result);

        if (result.is_open) {
            pthread_mutex_lock(&ctx->lock);
            if (ctx->results != NULL && ctx->open_ports_count < ctx->results_capacity) {
                ctx->results[ctx->open_ports_count] = result;
            }
            ctx->open_ports_count++;

            if (result.banner[0] != '\0') {
                printf("  [OPEN] %-5d/tcp  %-12s | Bannière: %.80s\n",
                       result.port, result.service_name, result.banner);
            } else {
                printf("  [OPEN] %-5d/tcp  %-12s\n",
                       result.port, result.service_name);
            }
            pthread_mutex_unlock(&ctx->lock);
        }
    }

    return NULL;
}

bool export_results_json(const char *filepath, const scan_context_t *ctx, double elapsed_sec) {
    FILE *fp = fopen(filepath, "w");
    if (fp == NULL) {
        perror("fopen");
        return false;
    }

    /* Tri des résultats par numéro de port croissant pour un JSON propre */
    if (ctx->results != NULL && ctx->open_ports_count > 1) {
        qsort(ctx->results, (size_t)ctx->open_ports_count, sizeof(port_result_t), compare_ports);
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"target\": ");
    write_json_escaped(fp, ctx->target_host);
    fprintf(fp, ",\n");
    fprintf(fp, "  \"resolved_ip\": \"%s\",\n", ctx->resolved_ip);
    fprintf(fp, "  \"port_range\": \"%d-%d\",\n", ctx->start_port, ctx->end_port);
    fprintf(fp, "  \"scan_duration_sec\": %.3f,\n", elapsed_sec);
    fprintf(fp, "  \"open_ports_count\": %d,\n", ctx->open_ports_count);
    fprintf(fp, "  \"open_ports\": [\n");

    for (int i = 0; i < ctx->open_ports_count; i++) {
        const port_result_t *r = &ctx->results[i];
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"port\": %d,\n", r->port);
        fprintf(fp, "      \"protocol\": \"tcp\",\n");
        fprintf(fp, "      \"service\": ");
        write_json_escaped(fp, r->service_name);
        fprintf(fp, ",\n");
        fprintf(fp, "      \"banner\": ");
        write_json_escaped(fp, r->banner);
        fprintf(fp, "\n    }%s\n", (i < ctx->open_ports_count - 1) ? "," : "");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    fclose(fp);
    return true;
}
