
// Developer: Sreeraj
// GitHub: https://github.com/s-r-e-e-r-a-j

#define _POSIX_C_SOURCE 200809L

#include "argon2_crack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <argon2.h>

static int b64_decode_char(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *in, size_t in_len,
                      unsigned char *out, size_t *out_len)
{
    size_t i = 0;
    size_t o = 0;

    while (i < in_len) {
        int v0 = b64_decode_char((unsigned char)in[i]);
        if (v0 < 0) return -1;
        ++i;

        if (i >= in_len) return -1;
        int v1 = b64_decode_char((unsigned char)in[i]);
        if (v1 < 0) return -1;
        ++i;

        out[o++] = (unsigned char)((v0 << 2) | (v1 >> 4));

        if (i >= in_len || in[i] == '=') {
            *out_len = o;
            return 0;
        }

        int v2 = b64_decode_char((unsigned char)in[i]);
        if (v2 < 0) return -1;
        ++i;

        out[o++] = (unsigned char)(((v1 & 0x0f) << 4) | (v2 >> 2));

        if (i >= in_len || in[i] == '=') {
            *out_len = o;
            return 0;
        }

        int v3 = b64_decode_char((unsigned char)in[i]);
        if (v3 < 0) return -1;
        ++i;

        out[o++] = (unsigned char)(((v2 & 0x03) << 6) | v3);
    }

    *out_len = o;
    return 0;
}

int argon2_parse(const char *encoded, argon2_params *params)
{
    if (!encoded || !params)
        return 0;

    memset(params, 0, sizeof(*params));

    const char *p = encoded;

    if (strncmp(p, "$argon2id$", 10) != 0)
        return 0;

    p += 10;

    if (strncmp(p, "v=", 2) != 0)
        return 0;
    p += 2;

    char *end = NULL;
    unsigned long version = strtoul(p, &end, 10);
    if (end == p || *end != '$')
        return 0;
    params->version = (unsigned int)version;
    p = end + 1;

    if (strncmp(p, "m=", 2) != 0)
        return 0;
    p += 2;

    unsigned long memory = strtoul(p, &end, 10);
    if (end == p || *end != ',')
        return 0;
    params->memory_kib = (unsigned int)memory;
    p = end + 1;

    if (strncmp(p, "t=", 2) != 0)
        return 0;
    p += 2;

    unsigned long iterations = strtoul(p, &end, 10);
    if (end == p || *end != ',')
        return 0;
    params->iterations = (unsigned int)iterations;
    p = end + 1;

    if (strncmp(p, "p=", 2) != 0)
        return 0;
    p += 2;

    unsigned long parallelism = strtoul(p, &end, 10);
    if (end == p || *end != '$')
        return 0;
    params->parallelism = (unsigned int)parallelism;
    p = end + 1;

    const char *salt_start = p;
    while (*p && *p != '$')
        ++p;
    if (*p != '$')
        return 0;

    size_t salt_b64_len = (size_t)(p - salt_start);
    if (salt_b64_len == 0 || salt_b64_len > 128)
        return 0;

    size_t salt_len = 0;
    if (b64_decode(salt_start, salt_b64_len, params->salt, &salt_len) != 0)
        return 0;
    params->salt_len = (unsigned int)salt_len;

    ++p;

    size_t hash_b64_len = strlen(p);
    if (hash_b64_len == 0 || hash_b64_len > 256)
        return 0;

    size_t hash_len = 0;
    if (b64_decode(p, hash_b64_len, params->hash, &hash_len) != 0)
        return 0;
    params->hash_len = (unsigned int)hash_len;

    if (params->memory_kib == 0 || params->iterations == 0 ||
        params->parallelism == 0)
        return 0;

    if (params->version != ARGON2_VERSION_10 &&
        params->version != ARGON2_VERSION_13)
        return 0;

    params->type = Argon2_id;

    size_t enc_len = strlen(encoded);
    if (enc_len >= ARGON2_MAX_ENCODED_LEN)
        return 0;
    memcpy(params->encoded, encoded, enc_len + 1);

    return 1;
}

int argon2id_check(const argon2_params *params, const char *password)
{
    if (!params || !password)
        return 0;

    unsigned char *computed = (unsigned char *)malloc(params->hash_len);
    if (!computed)
        return 0;

    int rc = argon2id_hash_raw(
        params->iterations,
        params->memory_kib,
        params->parallelism,
        password,
        strlen(password),
        params->salt,
        params->salt_len,
        computed,
        params->hash_len
    );

    if (rc != ARGON2_OK) {
        free(computed);
        return 0;
    }

    int match = (memcmp(computed, params->hash, params->hash_len) == 0);
    free(computed);
    return match;
}

void argon2_free(argon2_params *params)
{
    if (!params)
        return;
    memset(params, 0, sizeof(*params));
}
