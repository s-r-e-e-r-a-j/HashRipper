#!/usr/bin/env python3

# Developer: Sreeraj
# GitHub: https://github.com/s-r-e-e-r-a-j

try:
    try:
        from Crypto.Hash import MD2, MD4, RIPEMD
    except ImportError:
           from Cryptodome.Hash import MD2, MD4, RIPEMD
except:
       print(f"{RED}[!] Please install pycryptodome {RESET}")
       sys.exit(1)
    
import hashlib
import argparse
import concurrent.futures
import os
import sys
import threading

# ANSI color codes
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'

try:
    import crcmod
except ImportError:
    print(f"{RED}[!] Please install crcmod{RESET}")
    sys.exit(1)

import zlib

SUPPORTED_HASHES = {
    'md5': lambda data: hashlib.md5(data.encode()).hexdigest(),
    'sha1': lambda data: hashlib.sha1(data.encode()).hexdigest(),
    'sha224': lambda data: hashlib.sha224(data.encode()).hexdigest(),
    'sha256': lambda data: hashlib.sha256(data.encode()).hexdigest(),
    'sha384': lambda data: hashlib.sha384(data.encode()).hexdigest(),
    'sha512': lambda data: hashlib.sha512(data.encode()).hexdigest(),
    'sha3_224': lambda data: hashlib.sha3_224(data.encode()).hexdigest(),
    'sha3_256': lambda data: hashlib.sha3_256(data.encode()).hexdigest(),
    'sha3_384': lambda data: hashlib.sha3_384(data.encode()).hexdigest(),
    'sha3_512': lambda data: hashlib.sha3_512(data.encode()).hexdigest(),
    'blake2b': lambda data: hashlib.blake2b(data.encode()).hexdigest(),
    'blake2s': lambda data: hashlib.blake2s(data.encode()).hexdigest(),
    'ntlm': lambda data: MD4.new(data.encode('utf-16le')).hexdigest(),
    'md2': lambda data: MD2.new(data.encode()).hexdigest(),
    'md4': lambda data: MD4.new(data.encode()).hexdigest(),
    'ripemd_160': lambda data: RIPEMD.new(data.encode()).hexdigest(),
    'crc32': lambda data: format(zlib.crc32(data.encode()) & 0xFFFFFFFF, '08x'),
    'adler_32': lambda data: format(zlib.adler32(data.encode()) & 0xFFFFFFFF, '08x'),
}

crack_found_event = threading.Event()
cracked_password = None
lock = threading.Lock()

def check_word(word, target_hash, hash_func):
    global cracked_password
    word = word.strip()
    if crack_found_event.is_set():
        return False
    try:
        hashed = hash_func(word)
        if hashed.lower() == target_hash.lower():
            with lock:
                cracked_password = word
            crack_found_event.set()
            return True
    except Exception:
        pass
    return False

def crack_hash_threaded(target_hash, algorithm, wordlist_path, num_threads, output_file=None):
    global cracked_password

    if algorithm not in SUPPORTED_HASHES:
        print(f"{RED}[!] Unsupported hash algorithm: {algorithm}{RESET}")
        return False

    if not os.path.isfile(wordlist_path):
        print(f"{RED}[!] Wordlist not found: {wordlist_path}{RESET}")
        return False

    hash_func = SUPPORTED_HASHES[algorithm]
    print(f"{YELLOW}[*] Starting hash cracking using {algorithm} with {num_threads} threads...{RESET}")

    # Try utf-8 encoding first; if it fails, fallback to latin-1
    try:
        f = open(wordlist_path, 'r', encoding='utf-8', errors='ignore')
    except UnicodeDecodeError:
        f = open(wordlist_path, 'r', encoding='latin-1', errors='ignore')

    with f:
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = []
            for line in f:
                if crack_found_event.is_set():
                    break
                futures.append(executor.submit(check_word, line, target_hash, hash_func))

            for future in concurrent.futures.as_completed(futures):
                if crack_found_event.is_set():
                    break

    if cracked_password:
        print(f"{GREEN}[+] Hash cracked! Plaintext: {cracked_password}{RESET}")
        if output_file:
            try:
                with open(output_file, 'w') as f_out:
                    f_out.write(f"{target_hash} : {cracked_password}\n")
                print(f"{GREEN}[+] Saved result to: {output_file}{RESET}")
            except Exception as e:
                print(f"{RED}[!] Failed to save output: {e}{RESET}")
        return True
    else:
        print(f"{RED}[-] Hash not found in the wordlist.{RESET}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Efficient Multi-threaded Hash Cracker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-H", "--hash", help="Hash to crack")
    group.add_argument("--hashfile", help="File containing the hash (first line will be used)")

    parser.add_argument("-a", "--algorithm", required=True, help="Hash algorithm (e.g., md5, sha256, ripemd_160)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", help="Output file to save the cracked hash")

    args = parser.parse_args()

    if args.hashfile:
        if not os.path.isfile(args.hashfile):
            print(f"{RED}[!] Hash file not found: {args.hashfile}{RESET}")
            sys.exit(1)
        with open(args.hashfile, 'r') as f:
            target_hash = f.readline().strip()
    else:
        target_hash = args.hash.strip()

    success = crack_hash_threaded(target_hash, args.algorithm.lower(), args.wordlist, args.threads, args.output)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
     try:
         main()
     except KeyboardInterrupt:
             print(f"{RED} [!] User Aborted {RESET}")
             sys.exit()
