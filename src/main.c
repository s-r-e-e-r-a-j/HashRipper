
// Developer: Sreeraj
// GitHub: https://github.com/s-r-e-e-r-aj

#define _POSIX_C_SOURCE 200809L

#include "cracker.h"
#include "hash.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RED    "\033[91m"
#define GREEN  "\033[92m"
#define YELLOW "\033[93m"
#define RESET  "\033[0m"

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s (-H HASH | --hashfile FILE) -a ALGORITHM -w WORDLIST "
        "[-t THREADS] [-o OUTPUT]\n\n"
        "Options:\n"
        "  -H, --hash HASH       Target hash\n"
        "      --hashfile FILE  Read target hash from first line\n"
        "  -a, --algorithm NAME  Hash algorithm\n"
        "  -w, --wordlist FILE  Wordlist path\n"
        "  -t, --threads N      Worker threads (default: 10)\n"
        "  -o, --output FILE    Save successful result\n"
        "  -h, --help           Show this help\n\n"
        "Algorithms:\n"
        "  md5 sha1 sha224 sha256 sha384 sha512\n"
        "  sha3_224 sha3_256 sha3_384 sha3_512\n"
        "  blake2b blake2s ntlm md2 md4 ripemd_160\n"
        "  crc32 xxh32 xxh64 xxh3_64bits xxh3_128bits\n",
        prog);
}

static int read_first_line(const char *path, char **result)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, RED "[!] Hash file not found: %s" RESET "\n", path);
        return -1;
    }

    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, fp);
    fclose(fp);

    if (n < 0) {
        free(line);
        fprintf(stderr, RED "[!] Hash file is empty: %s" RESET "\n", path);
        return -1;
    }

    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
        line[--n] = '\0';

    *result = line;
    return 0;
}

static int save_result(const char *path, const char *target, const char *password)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, RED "[!] Failed to save output: %s" RESET "\n", path);
        return -1;
    }

    fprintf(fp, "%s : %s\n", target, password);
    fclose(fp);

    printf(GREEN "[+] Saved result to: %s" RESET "\n", path);
    return 0;
}

int main(int argc, char **argv)
{
    const char *hash_arg = NULL;
    const char *hashfile = NULL;
    const char *algorithm_arg = NULL;
    const char *wordlist = NULL;
    const char *output = NULL;
    unsigned int threads = 10;

    static const struct option long_options[] = {
        {"hash",      required_argument, 0, 'H'},
        {"hashfile",  required_argument, 0, 1000},
        {"algorithm", required_argument, 0, 'a'},
        {"wordlist",  required_argument, 0, 'w'},
        {"threads",   required_argument, 0, 't'},
        {"output",    required_argument, 0, 'o'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "H:a:w:t:o:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'H': hash_arg = optarg; break;
            case 1000: hashfile = optarg; break;
            case 'a': algorithm_arg = optarg; break;
            case 'w': wordlist = optarg; break;
            case 't': {
                char *end = NULL;
                unsigned long n = strtoul(optarg, &end, 10);
                if (!*optarg || *end || n < 1 || n > 4096) {
                    fprintf(stderr, RED "[!] Invalid thread count: %s" RESET "\n", optarg);
                    return 1;
                }
                threads = (unsigned int)n;
                break;
            }
            case 'o': output = optarg; break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if ((hash_arg && hashfile) || (!hash_arg && !hashfile) ||
        !algorithm_arg || !wordlist) {
        fprintf(stderr, RED "[!] Exactly one of --hash/--hashfile is required, "
                           "and --algorithm/--wordlist are required." RESET "\n");
        usage(argv[0]);
        return 1;
    }

    hash_algorithm algorithm = hash_algorithm_from_name(algorithm_arg);
    if (algorithm == HASH_INVALID) {
        fprintf(stderr, RED "[!] Unsupported hash algorithm: %s" RESET "\n",
                algorithm_arg);
        return 1;
    }

    char *target_alloc = NULL;
    const char *target_hash = hash_arg;

    if (hashfile) {
        if (read_first_line(hashfile, &target_alloc) != 0)
            return 1;
        target_hash = target_alloc;
    }

    crack_options options = {
        .target_hash = target_hash,
        .algorithm = algorithm,
        .wordlist_path = wordlist,
        .num_threads = threads,
        .output_path = output
    };

    char *password = NULL;
    int result = crack_hash(&options, &password);

    if (result == 1) {
        printf(GREEN "[+] Hash cracked! Plaintext: %s" RESET "\n", password);

        if (output)
            save_result(output, target_hash, password);

        free(password);
        free(target_alloc);
        return 0;
    }

    if (result == 0)
        printf(RED "[-] Hash not found in the wordlist." RESET "\n");

    free(target_alloc);
    return result < 0 ? 1 : 1;
}
