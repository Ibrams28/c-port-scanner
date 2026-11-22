#ifndef SCANNER_H
#define SCANNER_H

#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>

#define MAX_BANNER_LEN 256
#define DEFAULT_TIMEOUT_MS 200
#define DEFAULT_THREADS 50

/* Résultat de l'analyse d'un port individuel */
typedef struct {
    int port;
    bool is_open;
    char service_name[64];
    char banner[MAX_BANNER_LEN];
} port_result_t;

/* Configuration globale et état partagé du scan */
typedef struct {
    char target_host[256];
    char resolved_ip[INET_ADDRSTRLEN];
    struct in_addr target_addr;
    int start_port;
    int end_port;
    int timeout_ms;
    int current_port;
    int open_ports_count;
    port_result_t *results;         // Tableau dynamique des ports ouverts (protégé par mutex)
    int results_capacity;           // Capacité allouée pour le tableau
    pthread_mutex_t lock;
} scan_context_t;

bool resolve_target(const char *hostname, scan_context_t *ctx);
void scan_single_port(const scan_context_t *ctx, int port, port_result_t *result);
void *worker_thread(void *arg);
bool export_results_json(const char *filepath, const scan_context_t *ctx, double elapsed_sec);

#endif /* SCANNER_H */
