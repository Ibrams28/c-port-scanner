#define _POSIX_C_SOURCE 200809L

#include "scanner.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_usage(const char *prog_name) {
    printf("Usage: %s -t <cible> [-s <port_debut>] [-e <port_fin>] [-T <threads>] [-w <timeout_ms>] [-o <fichier.json>]\n\n", prog_name);
    printf("Options:\n");
    printf("  -t <cible>      Adresse IPv4 ou nom d'hôte (obligatoire)\n");
    printf("  -s <port>       Port de début (défaut: 1)\n");
    printf("  -e <port>       Port de fin (défaut: 1024)\n");
    printf("  -T <threads>    Nombre de threads concurrents (défaut: %d, max: 500)\n", DEFAULT_THREADS);
    printf("  -w <ms>         Timeout socket en millisecondes (défaut: %dms)\n", DEFAULT_TIMEOUT_MS);
    printf("  -o <fichier>    Exporte les résultats au format JSON\n");
    printf("  -h              Affiche cette aide\n");
}

int main(int argc, char *argv[]) {
    scan_context_t ctx;
    memset(&ctx, 0, sizeof(scan_context_t));

    ctx.start_port = 1;
    ctx.end_port = 1024;
    ctx.timeout_ms = DEFAULT_TIMEOUT_MS;
    int num_threads = DEFAULT_THREADS;
    char output_file[256] = {0};

    int opt;
    while ((opt = getopt(argc, argv, "t:s:e:T:w:o:h")) != -1) {
        switch (opt) {
            case 't':
                snprintf(ctx.target_host, sizeof(ctx.target_host), "%s", optarg);
                break;
            case 's':
                ctx.start_port = atoi(optarg);
                break;
            case 'e':
                ctx.end_port = atoi(optarg);
                break;
            case 'T':
                num_threads = atoi(optarg);
                break;
            case 'w':
                ctx.timeout_ms = atoi(optarg);
                break;
            case 'o':
                snprintf(output_file, sizeof(output_file), "%s", optarg);
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (ctx.target_host[0] == '\0') {
        fprintf(stderr, "[!] Erreur : cible manquante (-t).\n\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (ctx.start_port < 1 || ctx.end_port > 65535 || ctx.start_port > ctx.end_port) {
        fprintf(stderr, "[!] Erreur : plage de ports invalide (%d-%d).\n",
                ctx.start_port, ctx.end_port);
        return EXIT_FAILURE;
    }

    if (num_threads < 1 || num_threads > 500) {
        fprintf(stderr, "[!] Erreur : nombre de threads invalide (1-500).\n");
        return EXIT_FAILURE;
    }

    if (ctx.timeout_ms < 1 || ctx.timeout_ms > 60000) {
        fprintf(stderr, "[!] Erreur : timeout invalide (1-60000 ms).\n");
        return EXIT_FAILURE;
    }

    if (!resolve_target(ctx.target_host, &ctx)) {
        return EXIT_FAILURE;
    }

    int total_ports = ctx.end_port - ctx.start_port + 1;
    if (num_threads > total_ports) {
        num_threads = total_ports;
    }

    /* Allocation du tableau des résultats (si l'export JSON est demandé) */
    if (output_file[0] != '\0') {
        ctx.results_capacity = total_ports;
        ctx.results = malloc(sizeof(port_result_t) * (size_t)total_ports);
        if (ctx.results == NULL) {
            perror("malloc");
            return EXIT_FAILURE;
        }
    }

    ctx.current_port = ctx.start_port;
    if (pthread_mutex_init(&ctx.lock, NULL) != 0) {
        perror("pthread_mutex_init");
        free(ctx.results);
        return EXIT_FAILURE;
    }

    printf("============================================================\n");
    printf(" c-port-scanner | Cible: %s (%s)\n", ctx.target_host, ctx.resolved_ip);
    printf(" Plage: %d-%d | Threads: %d | Timeout: %dms\n",
           ctx.start_port, ctx.end_port, num_threads, ctx.timeout_ms);
    printf("============================================================\n");

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    pthread_t *threads = malloc(sizeof(pthread_t) * (size_t)num_threads);
    if (threads == NULL) {
        perror("malloc");
        pthread_mutex_destroy(&ctx.lock);
        free(ctx.results);
        return EXIT_FAILURE;
    }

    int created_threads = 0;
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, worker_thread, &ctx) != 0) {
            perror("pthread_create");
            break;
        }
        created_threads++;
    }

    for (int i = 0; i < created_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    printf("============================================================\n");
    printf(" Scan terminé en %.2fs : %d port(s) ouvert(s) sur %d.\n",
           elapsed, ctx.open_ports_count, total_ports);

    if (output_file[0] != '\0') {
        if (export_results_json(output_file, &ctx, elapsed)) {
            printf(" Résultats exportés dans : %s\n", output_file);
        } else {
            fprintf(stderr, " [!] Échec de l'export JSON vers : %s\n", output_file);
        }
    }
    printf("============================================================\n");

    free(threads);
    free(ctx.results);
    pthread_mutex_destroy(&ctx.lock);

    return EXIT_SUCCESS;
}
