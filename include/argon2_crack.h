
// Developer: Sreeraj
// GitHub: https://github.com/s-r-e-e-r-a-j

#ifndef ARGON2_CRACK_H
#define ARGON2_CRACK_H

#include <stddef.h>

#define ARGON2_MAX_ENCODED_LEN 512

typedef struct {
    unsigned int version;
    unsigned int type;
    unsigned int memory_kib;
    unsigned int iterations;
    unsigned int parallelism;
    unsigned int salt_len;
    unsigned int hash_len;
    unsigned char salt[64];
    unsigned char hash[128];
    char encoded[ARGON2_MAX_ENCODED_LEN];
} argon2_params;

int argon2_parse(const char *encoded, argon2_params *params);
int argon2id_check(const argon2_params *params, const char *password);
void argon2_free(argon2_params *params);

#endif
