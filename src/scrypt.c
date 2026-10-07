
// Developer: Sreeraj
// GitHub: https://github.com/s-r-e-e-r-a-j

#define _POSIX_C_SOURCE 200809L

#include "scrypt.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int standard_b64_value(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';

    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;

    if (c >= '0' && c <= '9')
        return c - '0' + 52;

    if (c == '+')
        return 62;

    if (c == '/')
        return 63;

    return -1;
}

static int crypt_b64_value(char c)
{
    if (c == '.')
        return 0;

    if (c == '/')
        return 1;

    if (c >= '0' && c <= '9')
        return c - '0' + 2;

    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 12;

    if (c >= 'a' && c <= 'z')
        return c - 'a' + 38;

    return -1;
}

static int b64_decode(const char *src,
                      int (*value_of)(char),
                      unsigned char **out,
                      size_t *out_len)
{
    if (!src || !out || !out_len)
        return 0;

    size_t len = strlen(src);

    if (len == 0 || (len % 4) == 1)
        return 0;

    size_t padded_len = len;

    if ((padded_len % 4) != 0)
        padded_len += 4 - (padded_len % 4);

    char *tmp = malloc(padded_len + 1);

    if (!tmp)
        return 0;

    memcpy(tmp, src, len);

    for (size_t i = len; i < padded_len; ++i)
        tmp[i] = '=';

    tmp[padded_len] = '\0';

    unsigned char *buf = malloc((padded_len / 4) * 3);

    if (!buf) {
        free(tmp);
        return 0;
    }

    size_t pos = 0;

    for (size_t i = 0; i < padded_len; i += 4) {
        int a = value_of(tmp[i]);
        int b = value_of(tmp[i + 1]);
        int c = 0;
        int d = 0;

        if (a < 0 || b < 0) {
            free(buf);
            free(tmp);
            return 0;
        }

        if (tmp[i + 2] != '=') {
            c = value_of(tmp[i + 2]);

            if (c < 0) {
                free(buf);
                free(tmp);
                return 0;
            }
        }

        if (tmp[i + 3] != '=') {
            d = value_of(tmp[i + 3]);

            if (d < 0) {
                free(buf);
                free(tmp);
                return 0;
            }
        }

        buf[pos++] = (unsigned char)((a << 2) | (b >> 4));

        if (tmp[i + 2] != '=')
            buf[pos++] = (unsigned char)((b << 4) | (c >> 2));

        if (tmp[i + 3] != '=')
            buf[pos++] = (unsigned char)((c << 6) | d);
    }

    free(tmp);

    *out = buf;
    *out_len = pos;

    return 1;
}

static int parse_uint(const char *str, unsigned int *out)
{
    if (!str || !*str || !out)
        return 0;

    char *end = NULL;

    unsigned long v = strtoul(str, &end, 10);

    if (end == str || *end != '\0')
        return 0;

    if (v == 0 || v > 0xffffffffUL)
        return 0;

    *out = (unsigned int)v;

    return 1;
}

static int parse_kv(const char *str, unsigned int *ln,
                    unsigned int *r, unsigned int *p)
{
    if (!str || !ln || !r || !p)
        return 0;

    char *copy = strdup(str);

    if (!copy)
        return 0;

    char *save = NULL;
    char *tok = strtok_r(copy, ",", &save);

    int got_ln = 0;
    int got_r  = 0;
    int got_p  = 0;

    while (tok) {
        if (strncmp(tok, "ln=", 3) == 0) {
            if (!parse_uint(tok + 3, ln)) { free(copy); return 0; }
            got_ln = 1;
        } else if (strncmp(tok, "r=", 2) == 0) {
            if (!parse_uint(tok + 2, r)) { free(copy); return 0; }
            got_r = 1;
        } else if (strncmp(tok, "p=", 2) == 0) {
            if (!parse_uint(tok + 2, p)) { free(copy); return 0; }
            got_p = 1;
        } else {
            free(copy);
            return 0;
        }

        tok = strtok_r(NULL, ",", &save);
    }

    free(copy);

    return got_ln && got_r && got_p;
}

static int parse_phc(const char *input, scrypt_params *params)
{
    char *copy = strdup(input);

    if (!copy)
        return 0;

    char *save = NULL;

    char *head    = strtok_r(copy, "$", &save);
    char *params_s = strtok_r(NULL, "$", &save);
    char *salt_s  = strtok_r(NULL, "$", &save);
    char *hash_s  = strtok_r(NULL, "$", &save);
    char *extra   = strtok_r(NULL, "$", &save);

    if (!head || !params_s || !salt_s || !hash_s || extra) {
        free(copy);
        return 0;
    }

    if (strcmp(head, "scrypt") != 0) {
        free(copy);
        return 0;
    }

    unsigned int ln = 0;
    unsigned int r  = 0;
    unsigned int p  = 0;

    if (!parse_kv(params_s, &ln, &r, &p)) {
        free(copy);
        return 0;
    }

    if (ln < 1 || ln > 20) { free(copy); return 0; }
    if (r  < 1 || r  > 32) { free(copy); return 0; }
    if (p  < 1 || p  > 16) { free(copy); return 0; }

    if (!b64_decode(salt_s, standard_b64_value,
                    &params->salt, &params->salt_len)) {
        free(copy);
        return 0;
    }

    if (!b64_decode(hash_s, standard_b64_value,
                    &params->target, &params->target_len)) {
        scrypt_free(params);
        free(copy);
        return 0;
    }

    params->format = SCRYPT_FORMAT_PHC;
    params->ln = ln;
    params->r  = r;
    params->p  = p;

    free(copy);

    return 1;
}

static int parse_mcf(const char *input, scrypt_params *params)
{
    char *copy = strdup(input);

    if (!copy)
        return 0;

    char *save = NULL;

    char *head    = strtok_r(copy, "$", &save);
    char *n_s     = strtok_r(NULL, "$", &save);
    char *r_s     = strtok_r(NULL, "$", &save);
    char *p_s     = strtok_r(NULL, "$", &save);
    char *salt_s  = strtok_r(NULL, "$", &save);
    char *hash_s  = strtok_r(NULL, "$", &save);
    char *extra   = strtok_r(NULL, "$", &save);

    if (!head || !n_s || !r_s || !p_s || !salt_s || !hash_s || extra) {
        free(copy);
        return 0;
    }

    if (strcmp(head, "7") != 0) {
        free(copy);
        return 0;
    }

    unsigned int N = 0;
    unsigned int r = 0;
    unsigned int p = 0;

    if (!parse_uint(n_s, &N)) { free(copy); return 0; }
    if (!parse_uint(r_s, &r)) { free(copy); return 0; }
    if (!parse_uint(p_s, &p)) { free(copy); return 0; }

    if (N < 2 || N > 0x10000000U) { free(copy); return 0; }
    if ((N & (N - 1)) != 0)        { free(copy); return 0; }
    if (r < 1 || r > 32)           { free(copy); return 0; }
    if (p < 1 || p > 16)           { free(copy); return 0; }

    unsigned int ln = 0;

    while ((1U << ln) < N && ln < 32)
        ++ln;

    if ((1U << ln) != N) {
        free(copy);
        return 0;
    }

    if (!b64_decode(salt_s, crypt_b64_value,
                    &params->salt, &params->salt_len)) {
        free(copy);
        return 0;
    }

    if (!b64_decode(hash_s, crypt_b64_value,
                    &params->target, &params->target_len)) {
        scrypt_free(params);
        free(copy);
        return 0;
    }

    params->format = SCRYPT_FORMAT_MCF;
    params->ln = ln;
    params->r  = r;
    params->p  = p;

    free(copy);

    return 1;
}

int scrypt_parse(const char *str, scrypt_params *params)
{
    if (!str || !params)
        return 0;

    memset(params, 0, sizeof(*params));

    if (strncmp(str, "$scrypt$", 8) == 0)
        return parse_phc(str, params);

    if (strncmp(str, "$7$", 3) == 0)
        return parse_mcf(str, params);

    return 0;
}

int scrypt_verify(const scrypt_params *params, const char *password)
{
    if (!params || !password)
        return 0;

    if (!params->salt || !params->target)
        return 0;

    if (params->salt_len == 0 || params->target_len == 0)
        return 0;

    if (params->ln == 0 || params->r == 0 || params->p == 0)
        return 0;

    uint64_t N = (uint64_t)1 << params->ln;

    unsigned char *derived = malloc(params->target_len);

    if (!derived)
        return 0;

    int ok = EVP_PBE_scrypt(password, strlen(password),
                            params->salt, params->salt_len,
                            N, params->r, params->p,
                            (uint64_t)128 * N * params->r * 2,
                            derived, params->target_len);

    if (!ok) {
        free(derived);
        return 0;
    }

    int match = CRYPTO_memcmp(derived, params->target,
                              params->target_len) == 0;

    free(derived);

    return match;
}

void scrypt_free(scrypt_params *params)
{
    if (!params)
        return;

    free(params->salt);
    free(params->target);

    memset(params, 0, sizeof(*params));
}
