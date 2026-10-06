// Developer: Sreeraj
// GitHub: https://github.com/s-r-e-e-r-a-j

#ifndef PBKDF2_H
#define PBKDF2_H

#include <stddef.h>

typedef enum {
    PBKDF2_SHA1,
    PBKDF2_SHA224,
    PBKDF2_SHA256,
    PBKDF2_SHA384,
    PBKDF2_SHA512
} pbkdf2_prf;

typedef struct {
    pbkdf2_prf prf;
    unsigned int iterations;

    unsigned char *salt;
    size_t salt_len;

    unsigned char *target;
    size_t target_len;
} pbkdf2_params;

int pbkdf2_parse(const char *str, pbkdf2_params *params);

int pbkdf2_verify(const pbkdf2_params *params,
                  const char *password);

void pbkdf2_free(pbkdf2_params *params);

const char *pbkdf2_prf_name(pbkdf2_prf prf);

#endif
