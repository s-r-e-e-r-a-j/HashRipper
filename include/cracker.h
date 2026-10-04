
// Developer: Sreeraj
// GitHub: https://github.com/s-r-e-e-r-a-j

#ifndef CRACKER_H
#define CRACKER_H

#include "hash.h"
#include <stddef.h>

typedef struct {
    const char *target_hash;
    hash_algorithm algorithm;
    const char *wordlist_path;
    unsigned int num_threads;
    const char *output_path;
} crack_options;

/* Returns 1 when found, 0 when not found, -1 on an operational error. */
int crack_hash(const crack_options *options, char **found_password);

#endif
