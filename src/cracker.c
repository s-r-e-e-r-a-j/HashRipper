
// Developer: Sreeraj
// GitHub: https://github.com/s-r-e-e-r-a-j

#define _POSIX_C_SOURCE 200809L

#include "cracker.h"
#include "pbkdf2.h"
#include "scrypt.h"

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>

#define LINE_INITIAL_CAP 256

typedef struct {
    FILE *fp;
    pthread_mutex_t file_lock;

    atomic_bool found;
    atomic_bool fatal_error;

    const crack_options *options;
    char *found_password;
    pthread_mutex_t result_lock;
    const pbkdf2_params *pbkdf2;
    const scrypt_params *scrypt;
} worker_context;

static char *trim_strip(char *s)
{
    size_t len = strlen(s);

    while (len > 0 && isspace((unsigned char)s[len - 1]))
        s[--len] = '\0';

    size_t start = 0;
    while (s[start] && isspace((unsigned char)s[start]))
        ++start;

    if (start)
        memmove(s, s + start, len - start + 1);

    return s;
}

static int read_line_dynamic(FILE *fp, char **line, size_t *capacity)
{
    if (!*line) {
        *capacity = LINE_INITIAL_CAP;
        *line = (char *)malloc(*capacity);
        if (!*line) return -1;
    }

    size_t len = 0;

    for (;;) {
        if (fgets(*line + len, (int)(*capacity - len), fp) == NULL) {
            if (len == 0)
                return 0; /* EOF */
            break;
        }

        len += strlen(*line + len);

        if (len > 0 && (*line)[len - 1] == '\n')
            break;

        if (feof(fp))
            break;

        if (*capacity - len < 2) {
            size_t new_cap = (*capacity) * 2;
            char *tmp = (char *)realloc(*line, new_cap);
            if (!tmp) return -1;
            *line = tmp;
            *capacity = new_cap;
        }
    }

    return 1;
}

static void *worker_main(void *arg)
{
    worker_context *ctx = (worker_context *)arg;
    char *line = NULL;
    size_t capacity = 0;

    size_t max_hex;

    if (ctx->options->algorithm == HASH_SHAKE128 || ctx->options->algorithm == HASH_SHAKE256) {
        max_hex = strlen(ctx->options->target_hash) + 1;
    } else {
       max_hex = hash_hex_size(ctx->options->algorithm);
    }

    char *hashed = (char *)malloc(max_hex);

    if (!hashed) {
       atomic_store(&ctx->fatal_error, true);
       free(line);
       return NULL;
    }

    for (;;) {
        if (atomic_load(&ctx->found) || atomic_load(&ctx->fatal_error))
            break;

        pthread_mutex_lock(&ctx->file_lock);
        int rc = read_line_dynamic(ctx->fp, &line, &capacity);
        pthread_mutex_unlock(&ctx->file_lock);

        if (rc == 0)
            break;

        if (rc < 0) {
            atomic_store(&ctx->fatal_error, true);
            break;
        }

        char *word = trim_strip(line);

        if (hash_string(ctx->options->algorithm, (const unsigned char *)word, strlen(word), hashed, max_hex) != 0) {
            continue;
        }

        if (strcasecmp(hashed, ctx->options->target_hash) == 0) {
            pthread_mutex_lock(&ctx->result_lock);

            if (!atomic_load(&ctx->found)) {
                ctx->found_password = strdup(word);
                if (!ctx->found_password) {
                    atomic_store(&ctx->fatal_error, true);
                } else {
                    atomic_store(&ctx->found, true);
                }
            }

            pthread_mutex_unlock(&ctx->result_lock);
            break;
        }
    }

    free(hashed);
    free(line);
    return NULL;
}

static void *pbkdf2_worker_main(void *arg)
{
    worker_context *ctx = (worker_context *)arg;
    char *line = NULL;
    size_t capacity = 0;

    for (;;) {
        if (atomic_load(&ctx->found) || atomic_load(&ctx->fatal_error))
            break;

        pthread_mutex_lock(&ctx->file_lock);
        int rc = read_line_dynamic(ctx->fp, &line, &capacity);
        pthread_mutex_unlock(&ctx->file_lock);

        if (rc == 0)
            break;

        if (rc < 0) {
            atomic_store(&ctx->fatal_error, true);
            break;
        }

        char *word = trim_strip(line);

        if (pbkdf2_verify(ctx->pbkdf2, word)) {
            pthread_mutex_lock(&ctx->result_lock);

            if (!atomic_load(&ctx->found)) {
                ctx->found_password = strdup(word);
                if (!ctx->found_password) {
                    atomic_store(&ctx->fatal_error, true);
                } else {
                    atomic_store(&ctx->found, true);
                }
            }

            pthread_mutex_unlock(&ctx->result_lock);
            break;
        }
    }

    free(line);
    return NULL;
}

static void *scrypt_worker_main(void *arg)
{
    worker_context *ctx = (worker_context *)arg;
    char *line = NULL;
    size_t capacity = 0;

    for (;;) {
        if (atomic_load(&ctx->found) || atomic_load(&ctx->fatal_error))
            break;

        pthread_mutex_lock(&ctx->file_lock);
        int rc = read_line_dynamic(ctx->fp, &line, &capacity);
        pthread_mutex_unlock(&ctx->file_lock);

        if (rc == 0)
            break;

        if (rc < 0) {
            atomic_store(&ctx->fatal_error, true);
            break;
        }

        char *word = trim_strip(line);

        if (scrypt_verify(ctx->scrypt, word)) {
            pthread_mutex_lock(&ctx->result_lock);

            if (!atomic_load(&ctx->found)) {
                ctx->found_password = strdup(word);
                if (!ctx->found_password) {
                    atomic_store(&ctx->fatal_error, true);
                } else {
                    atomic_store(&ctx->found, true);
                }
            }

            pthread_mutex_unlock(&ctx->result_lock);
            break;
        }
    }

    free(line);
    return NULL;
}

static int valid_thread_count(unsigned int n)
{
    return n >= 1 && n <= 4096;
}

int crack_hash(const crack_options *options, char **found_password)
{
    if (!options || !found_password)
        return -1;

    *found_password = NULL;

    if (options->algorithm == HASH_INVALID) {
        fprintf(stderr, "[!] Unsupported hash algorithm\n");
        return -1;
    }

    pbkdf2_params pbkdf2 = {0};
    const pbkdf2_params *pbkdf2_ptr = NULL;

    if (options->algorithm == HASH_PBKDF2) {
        if (!pbkdf2_parse(options->target_hash, &pbkdf2)) {
            fprintf(stderr, "[!] Invalid PBKDF2 hash format\n");
            return -1;
        }
        pbkdf2_ptr = &pbkdf2;

        printf("\033[93m [*] PBKDF2 PRF: %s, iterations: %u, "
               "derived key: %zu bytes\033[0m\n",
               pbkdf2_prf_name(pbkdf2.prf),
               pbkdf2.iterations,
               pbkdf2.target_len);
    }

    scrypt_params scrypt = {0};
    const scrypt_params *scrypt_ptr = NULL;

    if (options->algorithm == HASH_SCRYPT) {
        if (!scrypt_parse(options->target_hash, &scrypt)) {
            fprintf(stderr, "[!] Invalid scrypt hash format\n");
            pbkdf2_free(&pbkdf2);
            scrypt_free(&scrypt);
            return -1;
        }

        scrypt_ptr = &scrypt;

        printf("\033[93m [*] scrypt: ln=%u r=%u p=%u, "
               "derived key: %zu bytes\033[0m\n",
               scrypt.ln, scrypt.r, scrypt.p, scrypt.target_len);
    }

    if (options->algorithm == HASH_SHAKE128 || options->algorithm == HASH_SHAKE256) {

        size_t target_len = strlen(options->target_hash);

        if (target_len == 0 || (target_len % 2) != 0) {
           fprintf(stderr, "[!] Invalid SHAKE target hash length\n");
           pbkdf2_free(&pbkdf2);
           scrypt_free(&scrypt);
           return -1;
        }

        for (size_t i = 0; i < target_len; ++i) {
            if (!isxdigit((unsigned char)options->target_hash[i])) {
               fprintf(stderr, "[!] Invalid SHAKE target hash\n");
               pbkdf2_free(&pbkdf2);
               scrypt_free(&scrypt);
               return -1;
            }
        }
    }

    if (!valid_thread_count(options->num_threads)) {
        fprintf(stderr, "[!] Thread count must be between 1 and 4096\n");
        pbkdf2_free(&pbkdf2);
        scrypt_free(&scrypt);
        return -1;
    }

    FILE *fp = fopen(options->wordlist_path, "rb");
    if (!fp) {
        fprintf(stderr, "[!] Cannot open wordlist '%s': %s\n", options->wordlist_path, strerror(errno));
        pbkdf2_free(&pbkdf2);
        scrypt_free(&scrypt);
        return -1;
    }

    worker_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.fp = fp;
    ctx.options = options;
    ctx.pbkdf2 = pbkdf2_ptr;
    ctx.scrypt = scrypt_ptr;

    pthread_mutex_init(&ctx.file_lock, NULL);
    pthread_mutex_init(&ctx.result_lock, NULL);
    atomic_init(&ctx.found, false);
    atomic_init(&ctx.fatal_error, false);

    pthread_t *threads = (pthread_t *)calloc(options->num_threads, sizeof(*threads));
    if (!threads) {
        fclose(fp);
        pthread_mutex_destroy(&ctx.file_lock);
        pthread_mutex_destroy(&ctx.result_lock);
        pbkdf2_free(&pbkdf2);
        scrypt_free(&scrypt);
        return -1;
    }

    printf("\033[93m [*] Starting hash cracking using %s with %u threads...\n \033[0m",
           hash_algorithm_name(options->algorithm), options->num_threads);

    void *(*worker_fn)(void *);

    switch (options->algorithm) {
    case HASH_PBKDF2:
        worker_fn = pbkdf2_worker_main;
        break;
    case HASH_SCRYPT:
        worker_fn = scrypt_worker_main;
        break;
    default:
        worker_fn = worker_main;
        break;
    }

    unsigned int created = 0;
    for (unsigned int i = 0; i < options->num_threads; ++i) {
        int rc = pthread_create(&threads[i], NULL, worker_fn, &ctx);
        if (rc != 0) {
            fprintf(stderr, "[!] Failed to create thread %u: %s\n", i + 1, strerror(rc));
            atomic_store(&ctx.fatal_error, true);
            break;
        }
        ++created;
    }

    for (unsigned int i = 0; i < created; ++i)
        pthread_join(threads[i], NULL);

    free(threads);
    fclose(fp);

    if (atomic_load(&ctx.fatal_error) && !atomic_load(&ctx.found)) {
        fprintf(stderr, "[!] Worker error occurred\n");
        free(ctx.found_password);
        pthread_mutex_destroy(&ctx.file_lock);
        pthread_mutex_destroy(&ctx.result_lock);
        pbkdf2_free(&pbkdf2);
        scrypt_free(&scrypt);
        return -1;
    }

    if (ctx.found_password) {
        *found_password = ctx.found_password;
        pthread_mutex_destroy(&ctx.file_lock);
        pthread_mutex_destroy(&ctx.result_lock);
        pbkdf2_free(&pbkdf2);
        scrypt_free(&scrypt);
        return 1;
    }

    pthread_mutex_destroy(&ctx.file_lock);
    pthread_mutex_destroy(&ctx.result_lock);
    pbkdf2_free(&pbkdf2);
    scrypt_free(&scrypt);
    return 0;
}
