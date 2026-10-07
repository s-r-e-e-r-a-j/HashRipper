#ifndef SCRYPT_H
#define SCRYPT_H

#include <stddef.h>

typedef enum {
    SCRYPT_FORMAT_PHC,
    SCRYPT_FORMAT_MCF
} scrypt_format;

typedef struct {
    scrypt_format format;

    unsigned int ln;
    unsigned int r;
    unsigned int p;

    unsigned char *salt;
    size_t salt_len;

    unsigned char *target;
    size_t target_len;
} scrypt_params;

int scrypt_parse(const char *str, scrypt_params *params);

int scrypt_verify(const scrypt_params *params, const char *password);

void scrypt_free(scrypt_params *params);

#endif
