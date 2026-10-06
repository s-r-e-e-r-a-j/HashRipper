
// Developer: Sreeraj
// GitHub: https://github.com/s-r-e-e-r-a-j

#define _POSIX_C_SOURCE 200809L

#include "pbkdf2.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static const EVP_MD *get_digest(pbkdf2_prf prf)
{
    switch (prf) {
    case PBKDF2_SHA1:
        return EVP_sha1();

    case PBKDF2_SHA224:
        return EVP_sha224();

    case PBKDF2_SHA256:
        return EVP_sha256();

    case PBKDF2_SHA384:
        return EVP_sha384();

    case PBKDF2_SHA512:
        return EVP_sha512();

    default:
        return NULL;
    }
}

const char *pbkdf2_prf_name(pbkdf2_prf prf)
{
    switch (prf) {
    case PBKDF2_SHA1:
        return "sha1";

    case PBKDF2_SHA224:
        return "sha224";

    case PBKDF2_SHA256:
        return "sha256";

    case PBKDF2_SHA384:
        return "sha384";

    case PBKDF2_SHA512:
        return "sha512";

    default:
        return "unknown";
    }
}

static int parse_prf(const char *name, pbkdf2_prf *prf)
{
    if (!name || !prf)
        return 0;

    if (strcmp(name, "sha1") == 0) {
        *prf = PBKDF2_SHA1;
        return 1;
    }

    if (strcmp(name, "sha224") == 0) {
        *prf = PBKDF2_SHA224;
        return 1;
    }

    if (strcmp(name, "sha256") == 0) {
        *prf = PBKDF2_SHA256;
        return 1;
    }

    if (strcmp(name, "sha384") == 0) {
        *prf = PBKDF2_SHA384;
        return 1;
    }

    if (strcmp(name, "sha512") == 0) {
        *prf = PBKDF2_SHA512;
        return 1;
    }

    return 0;
}

static int parse_iterations(const char *str,
                            unsigned int *iterations)
{
    if (!str || !*str || !iterations)
        return 0;

    char *end = NULL;

    unsigned long value = strtoul(str, &end, 10);

    if (end == str || *end != '\0')
        return 0;

    if (value < 1 || value > UINT_MAX)
        return 0;

    *iterations = (unsigned int)value;

    return 1;
}

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


static int standard_b64_decode(const char *src,
                               unsigned char **out,
                               size_t *out_len)
{
    if (!src || !out || !out_len)
        return 0;

    size_t len = strlen(src);

    if (len == 0 || (len % 4) != 0)
        return 0;

    size_t max_len = (len / 4) * 3;

    unsigned char *buf = malloc(max_len);

    if (!buf)
        return 0;

    size_t pos = 0;

    for (size_t i = 0; i < len; i += 4) {
        char a_char = src[i];
        char b_char = src[i + 1];
        char c_char = src[i + 2];
        char d_char = src[i + 3];

        int a = standard_b64_value(a_char);
        int b = standard_b64_value(b_char);

        if (a < 0 || b < 0) {
            free(buf);
            return 0;
        }

        int c = 0;
        int d = 0;

        if (c_char != '=') {
            c = standard_b64_value(c_char);

            if (c < 0) {
                free(buf);
                return 0;
            }
        }

        if (d_char != '=') {
            d = standard_b64_value(d_char);

            if (d < 0) {
                free(buf);
                return 0;
            }
        }

        if ((c_char == '=' || d_char == '=') &&
            i + 4 != len) {
            free(buf);
            return 0;
        }

        if (c_char == '=' && d_char != '=') {
            free(buf);
            return 0;
        }

        buf[pos++] = (unsigned char)((a << 2) | (b >> 4));

        if (c_char != '=') {
            buf[pos++] = (unsigned char)((b << 4) | (c >> 2));
        }

        if (d_char != '=') {
            buf[pos++] = (unsigned char)((c << 6) | d);
        }
    }

    *out = buf;
    *out_len = pos;

    return 1;
}

static int passlib_b64_value(char c)
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


static int passlib_b64_decode(const char *src,
                              unsigned char **out,
                              size_t *out_len)
{
    if (!src || !out || !out_len)
        return 0;

    size_t len = strlen(src);

    if (len == 0)
        return 0;

    for (size_t i = 0; i < len; ++i) {
        if (passlib_b64_value(src[i]) < 0) {
            return 0;
        }
    }

    if ((len % 4) == 1)
        return 0;

    size_t padded_len = len;

    if ((padded_len % 4) != 0)
        padded_len += 4 - (padded_len % 4);

    char *tmp = malloc(padded_len + 1);

    if (!tmp)
        return 0;

    for (size_t i = 0; i < len; ++i) {
        if (src[i] == '.')
            tmp[i] = '+';
        else
            tmp[i] = src[i];
    }

    for (size_t i = len; i < padded_len; ++i)
        tmp[i] = '=';

    tmp[padded_len] = '\0';

    int result = standard_b64_decode(
            tmp,
            out,
            out_len
        );

    free(tmp);

    return result;
}

static int copy_literal_salt(const char *salt,
                             pbkdf2_params *p)
{
    size_t len = strlen(salt);

    if (len == 0)
        return 0;

    p->salt = malloc(len);

    if (!p->salt)
        return 0;

    memcpy(p->salt, salt, len);

    p->salt_len = len;

    return 1;
}

static int parse_django(const char *input,
                        pbkdf2_params *p)
{
    char *copy = strdup(input);

    if (!copy)
        return 0;

    char *save = NULL;

    char *algorithm = strtok_r(copy, "$", &save);

    char *iterations = strtok_r(NULL, "$", &save);

    char *salt = strtok_r(NULL, "$", &save);

    char *target = strtok_r(NULL, "$", &save);

    char *extra = strtok_r(NULL, "$", &save);

    if (!algorithm || !iterations || !salt || !target || extra) {
        free(copy);
        return 0;
    }

    if (strncmp(algorithm, "pbkdf2_", 7) != 0) {
        free(copy);
        return 0;
    }

    if (!parse_prf(algorithm + 7, &p->prf)) {
        free(copy);
        return 0;
    }

    if (!parse_iterations(iterations, &p->iterations)) {
        free(copy);
        return 0;
    }

    if (!copy_literal_salt(salt, p)) {
        free(copy);
        return 0;
    }

    if (!standard_b64_decode(target, &p->target, &p->target_len)) {
        pbkdf2_free(p);
        free(copy);
        return 0;
    }

    free(copy);

    return 1;
}

static int parse_passlib(const char *input,
                         pbkdf2_params *p)
{
    if (strncmp(input, "$pbkdf2-", 8) != 0)
        return 0;

    char *copy = strdup(input + 1);

    if (!copy)
        return 0;

    char *save = NULL;

    char *algorithm = strtok_r(copy, "$", &save);

    char *iterations = strtok_r(NULL, "$", &save);

    char *salt = strtok_r(NULL, "$", &save);

    char *target = strtok_r(NULL, "$", &save);

    char *extra = strtok_r(NULL, "$", &save);

    if (!algorithm || !iterations || !salt || !target || extra) {
        free(copy);
        return 0;
    }

    if (strncmp(algorithm, "pbkdf2-", 7) != 0) {
        free(copy);
        return 0;
    }

    if (!parse_prf(algorithm + 7, &p->prf)) {
        free(copy);
        return 0;
    }

    if (!parse_iterations(iterations, &p->iterations)) {
        free(copy);
        return 0;
    }

    if (!passlib_b64_decode(salt, &p->salt, &p->salt_len)) {
        free(copy);
        return 0;
    }

    if (!passlib_b64_decode(target, &p->target, &p->target_len)) {
        pbkdf2_free(p);
        free(copy);
        return 0;
    }

    free(copy);

    return 1;
}

int pbkdf2_parse(const char *str,
                 pbkdf2_params *params)
{
    if (!str || !params)
        return 0;

    memset(params, 0, sizeof(*params));

    if (strncmp(str, "pbkdf2_", 7) == 0)
        return parse_django(str, params);

    if (strncmp(str, "$pbkdf2-", 8) == 0)
        return parse_passlib(str, params);

    return 0;
}

int pbkdf2_verify(const pbkdf2_params *params,
                  const char *password)
{
    if (!params || !password)
        return 0;

    const EVP_MD *md = get_digest(params->prf);

    if (!md || !params->salt || !params->target ||
        params->salt_len == 0 ||
        params->target_len == 0 ||
        params->iterations == 0) {
        return 0;
    }

    unsigned char *derived = malloc(params->target_len);

    if (!derived)
        return 0;

    int ok = PKCS5_PBKDF2_HMAC(
            password,
            -1,
            params->salt,
            (int)params->salt_len,
            (int)params->iterations,
            md,
            (int)params->target_len,
            derived
        );

    if (!ok) {
        free(derived);
        return 0;
    }

    int match = CRYPTO_memcmp(
            derived,
            params->target,
            params->target_len
        ) == 0;

    free(derived);

    return match;
}

void pbkdf2_free(pbkdf2_params *params)
{
    if (!params)
        return;

    free(params->salt);
    free(params->target);

    memset(params, 0, sizeof(*params));
}
