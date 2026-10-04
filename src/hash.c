
// Developer: Sreeraj
// GitHub: https://github.com/s-r-e-e-r-a-j

#include "hash.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <zlib.h>
#include <xxhash.h>

static int ci_equal(const char *a, const char *b)
{
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;
        if (tolower(ca) != tolower(cb))
            return 0;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

hash_algorithm hash_algorithm_from_name(const char *name)
{
    if (!name) return HASH_INVALID;
    if (ci_equal(name, "md5"))        return HASH_MD5;
    if (ci_equal(name, "sha1"))       return HASH_SHA1;
    if (ci_equal(name, "sha224"))     return HASH_SHA224;
    if (ci_equal(name, "sha256"))     return HASH_SHA256;
    if (ci_equal(name, "sha384"))     return HASH_SHA384;
    if (ci_equal(name, "sha512"))     return HASH_SHA512;
    if (ci_equal(name, "sha3_224"))   return HASH_SHA3_224;
    if (ci_equal(name, "sha3_256"))   return HASH_SHA3_256;
    if (ci_equal(name, "sha3_384"))   return HASH_SHA3_384;
    if (ci_equal(name, "sha3_512"))   return HASH_SHA3_512;
    if (ci_equal(name, "blake2b"))    return HASH_BLAKE2B;
    if (ci_equal(name, "blake2s"))    return HASH_BLAKE2S;
    if (ci_equal(name, "ntlm"))       return HASH_NTLM;
    if (ci_equal(name, "md2"))        return HASH_MD2;
    if (ci_equal(name, "md4"))        return HASH_MD4;
    if (ci_equal(name, "ripemd_160") || ci_equal(name, "ripemd160"))
        return HASH_RIPEMD160;
    if (ci_equal(name, "crc32"))      return HASH_CRC32;
    if (ci_equal(name, "whirlpool"))  return HASH_WHIRLPOOL;
    if (ci_equal(name, "sm3"))        return HASH_SM3;
    if (ci_equal(name, "sha512_224")) return HASH_SHA512_224;
    if (ci_equal(name, "sha512_256")) return HASH_SHA512_256;
    if (ci_equal(name, "xxh32"))      return HASH_XXH32;
    if (ci_equal(name, "xxh64"))      return HASH_XXH64;
    if (ci_equal(name, "xxh3_64bits") || ci_equal(name, "xxh3_64"))
        return HASH_XXH3_64;
    if (ci_equal(name, "xxh3_128bits") || ci_equal(name, "xxh3_128"))
        return HASH_XXH3_128;
    return HASH_INVALID;
}

const char *hash_algorithm_name(hash_algorithm algorithm)
{
    static const char *names[] = {
        "md5", "sha1", "sha224", "sha256", "sha384", "sha512",
        "sha3_224", "sha3_256", "sha3_384", "sha3_512",
        "blake2b", "blake2s", "ntlm", "md2", "md4", "ripemd_160",
        "crc32", "whirlpool", "sm3", "sha512_224", "sha512_256", "xxh32", "xxh64", "xxh3_64bits", "xxh3_128bits", "invalid"
    };
    if (algorithm < HASH_MD5 || algorithm > HASH_XXH3_128)
        return names[HASH_INVALID];
    return names[algorithm];
}

static size_t digest_size(hash_algorithm algorithm)
{
    switch (algorithm) {
        case HASH_MD5:        return 16;
        case HASH_SHA1:       return 20;
        case HASH_SHA224:     return 28;
        case HASH_SHA256:     return 32;
        case HASH_SHA384:     return 48;
        case HASH_SHA512:     return 64;
        case HASH_SHA3_224:   return 28;
        case HASH_SHA3_256:   return 32;
        case HASH_SHA3_384:   return 48;
        case HASH_SHA3_512:   return 64;
        case HASH_BLAKE2B:    return 64;
        case HASH_BLAKE2S:    return 32;
        case HASH_NTLM:       return 16;
        case HASH_MD2:        return 16;
        case HASH_MD4:        return 16;
        case HASH_RIPEMD160:  return 20;
        case HASH_CRC32:      return 4;
        case HASH_WHIRLPOOL:  return 64;
        case HASH_SM3:        return 32;
        case HASH_SHA512_224: return 28;
        case HASH_SHA512_256: return 32;
        case HASH_XXH32:      return 4;
        case HASH_XXH64:      return 8;
        case HASH_XXH3_64:    return 8;
        case HASH_XXH3_128:   return 16;
        default:              return 0;
    }
}

size_t hash_hex_size(hash_algorithm algorithm)
{
    size_t n = digest_size(algorithm);
    return n ? (n * 2 + 1) : 0;
}

static const char *evp_name(hash_algorithm algorithm)
{
    switch (algorithm) {
        case HASH_MD5:       return "MD5";
        case HASH_SHA1:      return "SHA1";
        case HASH_SHA224:    return "SHA224";
        case HASH_SHA256:    return "SHA256";
        case HASH_SHA384:    return "SHA384";
        case HASH_SHA512:    return "SHA512";
        case HASH_SHA3_224:  return "SHA3-224";
        case HASH_SHA3_256:  return "SHA3-256";
        case HASH_SHA3_384:  return "SHA3-384";
        case HASH_SHA3_512:  return "SHA3-512";
        case HASH_BLAKE2B:   return "BLAKE2B-512";
        case HASH_BLAKE2S:   return "BLAKE2S-256";
        case HASH_MD2:       return "MD2";
        case HASH_MD4:       return "MD4";
        case HASH_RIPEMD160: return "RIPEMD-160";
        case HASH_WHIRLPOOL: return "WHIRLPOOL";
        case HASH_SM3:       return "SM3";
        case HASH_SHA512_224: return "SHA512-224";
        case HASH_SHA512_256: return "SHA512_256";
        default:             return NULL;
    }
}

static void hex_encode(const unsigned char *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int utf8_to_utf16le(const unsigned char *in, size_t len,
                           unsigned char **out, size_t *out_len)
{
    size_t cap = len ? len * 2 : 2;
    unsigned char *buf = (unsigned char *)malloc(cap);
    if (!buf) return -1;

    size_t used = 0, i = 0;
    while (i < len) {
        uint32_t cp;
        unsigned char c = in[i++];

        if (c < 0x80) {
            cp = c;
        } else if ((c & 0xe0) == 0xc0 && i < len &&
                   (in[i] & 0xc0) == 0x80) {
            cp = ((uint32_t)(c & 0x1f) << 6) | (in[i++] & 0x3f);
            if (cp < 0x80) goto invalid;
        } else if ((c & 0xf0) == 0xe0 && i + 1 < len &&
                   (in[i] & 0xc0) == 0x80 &&
                   (in[i + 1] & 0xc0) == 0x80) {
            unsigned char c1 = in[i++];
            unsigned char c2 = in[i++];
            cp = ((uint32_t)(c & 0x0f) << 12) |
                 ((uint32_t)(c1 & 0x3f) << 6) |
                 (c2 & 0x3f);
            if (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff)) goto invalid;
        } else if ((c & 0xf8) == 0xf0 && i + 2 < len &&
                   (in[i] & 0xc0) == 0x80 &&
                   (in[i + 1] & 0xc0) == 0x80 &&
                   (in[i + 2] & 0xc0) == 0x80) {
            unsigned char c1 = in[i++];
            unsigned char c2 = in[i++];
            unsigned char c3 = in[i++];
            cp = ((uint32_t)(c & 0x07) << 18) |
                 ((uint32_t)(c1 & 0x3f) << 12) |
                 ((uint32_t)(c2 & 0x3f) << 6) |
                 (c3 & 0x3f);
            if (cp < 0x10000 || cp > 0x10ffff) goto invalid;
        } else {
            goto invalid;
        }

        if (used + 4 > cap) {
            size_t new_cap = cap * 2;
            while (used + 4 > new_cap) new_cap *= 2;
            unsigned char *tmp = (unsigned char *)realloc(buf, new_cap);
            if (!tmp) { free(buf); return -1; }
            buf = tmp;
            cap = new_cap;
        }

        if (cp <= 0xffff) {
            buf[used++] = (unsigned char)(cp & 0xff);
            buf[used++] = (unsigned char)(cp >> 8);
        } else {
            uint32_t x = cp - 0x10000;
            uint16_t hi = (uint16_t)(0xd800 | (x >> 10));
            uint16_t lo = (uint16_t)(0xdc00 | (x & 0x3ff));
            buf[used++] = (unsigned char)(hi & 0xff);
            buf[used++] = (unsigned char)(hi >> 8);
            buf[used++] = (unsigned char)(lo & 0xff);
            buf[used++] = (unsigned char)(lo >> 8);
        }
    }

    *out = buf;
    *out_len = used;
    return 0;

invalid:
    free(buf);
    return -1;
}

static int openssl_digest(hash_algorithm algorithm,
                          const unsigned char *data, size_t len,
                          unsigned char *digest, size_t *digest_len)
{
    const char *name = evp_name(algorithm);
    if (!name) return -1;

    EVP_MD *md = EVP_MD_fetch(NULL, name, NULL);
    if (!md) {
        OSSL_PROVIDER_load(NULL, "legacy");
        md = EVP_MD_fetch(NULL, name, NULL);
    }
    if (!md) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_MD_free(md);
        return -1;
    }

    unsigned int out_len = 0;
    int ok = EVP_DigestInit_ex(ctx, md, NULL) == 1 &&
             EVP_DigestUpdate(ctx, data, len) == 1 &&
             EVP_DigestFinal_ex(ctx, digest, &out_len) == 1;

    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);

    if (!ok) return -1;
    *digest_len = out_len;
    return 0;
}

static int hash_numeric32(uint32_t value, char *output, size_t output_size)
{
    if (output_size < 9) return -1;
    snprintf(output, output_size, "%08x", value);
    return 0;
}

int hash_string(hash_algorithm algorithm,
                const unsigned char *data, size_t len,
                char *output, size_t output_size)
{
    if (!data || !output || algorithm == HASH_INVALID)
        return -1;

    size_t required = hash_hex_size(algorithm);
    if (!required || output_size < required)
        return -1;

    if (algorithm == HASH_CRC32) {
        uint32_t v = (uint32_t)crc32(0L, data, (uInt)len);
        return hash_numeric32(v, output, output_size);
    }

    if (algorithm == HASH_XXH32) {
        return hash_numeric32(XXH32(data, len, 0), output, output_size);
    }

    if (algorithm == HASH_XXH64) {
        if (output_size < 17) return -1;
        snprintf(output, output_size, "%016llx",
                 (unsigned long long)XXH64(data, len, 0));
        return 0;
    }

    if (algorithm == HASH_XXH3_64) {
        if (output_size < 17) return -1;
        snprintf(output, output_size, "%016llx",
                 (unsigned long long)XXH3_64bits(data, len));
        return 0;
    }

    if (algorithm == HASH_XXH3_128) {
        if (output_size < 33) return -1;
        XXH128_hash_t v = XXH3_128bits(data, len);
        snprintf(output, output_size, "%016llx%016llx",
                 (unsigned long long)v.high64,
                 (unsigned long long)v.low64);
        return 0;
    }

    const unsigned char *input = data;
    size_t input_len = len;
    unsigned char *converted = NULL;

    if (algorithm == HASH_NTLM) {
        if (utf8_to_utf16le(data, len, &converted, &input_len) != 0)
            return -1;
        input = converted;
        algorithm = HASH_MD4;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t digest_len = 0;
    int rc = openssl_digest(algorithm, input, input_len, digest, &digest_len);
    free(converted);

    if (rc != 0) return -1;

    hex_encode(digest, digest_len, output);
    return 0;
}
