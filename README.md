#  HashRipper

**HashRipper** is a powerful and fast multi-threaded ethical hacking tool written in C for cracking hashes. It supports over 28+ popular hash algorithms including NTLM, MD5, SHA variants, BLAKE2 and more. HashRipper uses a dictionary-based attack and multi-threading to crack hashes efficiently.

---

##  Features

-  **Multi-threaded** cracking for maximum speed
-  Supports **28+ hash algorithms**
-  Crack hashes from command-line or from file
-  Option to save cracked results to file
-  Simple and clean command-line interface
-  Works on Linux, Termux

---

## Disclaimer
HashRipper should be used responsibly and legally. Unauthorized use of this tool to crack hashes without permission is illegal and unethical. The author is not responsible for any misuse and it should only be used in controlled environments or on systems for which you have explicit authorization.

---

## Dependencies
- GCC / Clang
- Make
- OpenSSL
- xxHash
- zlib

The tool automatically detects the environment and installs its dependencies if any are missing.

---

## Compatibility
- Linux (Debian, RHEL, Arch, etc.)
- Termux (Android)

The tool automatically detects the environment and installs itself.

---

## Supported Hash Algorithms

`md5`

`sha1`

`sha224`

`sha256`

`sha384`

`sha512`

`sha512_224`

`sha512_256`

`sha3_224`

`sha3_256`

`sha3_384`

`sha3_512`

`blake2b`

`blake2s`

`ntlm`

`md2`

`md4`

`ripemd_160`

`crc32`

`whirlpool`

`sm3`

`shake128`

`shake256`

`pbkdf2` (only Django and Passlib formats are supported)

`scrypt` (Supports PHC and DragonFly/OpenBSD MCF formats only)

`xxh32`
 
`xxh64`

`xxh3_64bits`
 
`xxh3_128bits`

---

## installation

**1. Clone the Repository**
```bash
git clone https://github.com/s-r-e-e-r-a-j/HashRipper.git
```
**2. Navigate to the HashRipper directory**
```bash
cd HashRipper
```
**3. Run Installer**

*Linux*
```bash
sudo bash install.sh
```
*Termux*
```bash
bash install.sh
```
**4. Run the tool**
```bash
hashripper [options]
```

---

##  Command-Line Options

| Option            | Description                                                      |
|-------------------|------------------------------------------------------------------|
| `-H`, `--hash`     | Hash string to crack                                             |
| `--hashfile`       | File containing the hash (first line will be used)              |
| `-a`, `--algorithm`| Hash algorithm to use (see supported list above)                |
| `-w`, `--wordlist` | Path to the dictionary/wordlist file                            |
| `-t`, `--threads`  | Number of threads to use (default: 10)                          |
| `-o`, `--output`   | File to save cracked hash result                                |

> 🔸 **Note:** Either `--hash` or `--hashfile` must be specified.

---

## Example Usage
**Crack a hash using 20 threads:**
```bash
hashripper -H 5d41402abc4b2a76b9719d911017c592 -a md5 -w /usr/share/wordlists/rockyou.txt -t 20
```
**Crack from a file and save result:**
```bash
hashripper --hashfile /home/kali/Desktop/hash.txt -a sha256 -w /home/kali/Desktop/wordlist.txt -o /home/kali/Desktop/cracked.txt
```
**Crack a pbkdf2 hash using 20 threads**

> Note: Put PBKDF2 hashes in single quotes — `'pbkdf2_sha256$...$...$...'`. They contain `$` signs. The shell treats `$` as a variable, so without quotes the hash breaks. Other hashes (md5, sha256, …) are just hex, so they do not need quotes.

```bash
hashripper -H '$pbkdf2-sha256$29000$LOXc25tzDiEkZGxtzdkb4w$VZ/1.JD.V0wIU7TOgYbM/OZQ0bysXDOdSgocBWVy5ok' -a pbkdf2 -w wordlist.txt -t 20
```

**Crack a scrypt hash using 15 threads**

> Note: Put scrypt hashes in single quotes — `'$scrypt$ln=16,r=8,p=1$...$...'` or `'$7$16384$8$1$...$...'`. They contain `$` signs. The shell treats `$` as a variable, so without quotes the hash breaks. Other hashes (md5, sha256, …) are just hex, so they do not need quotes.

```bash
hashripper -H '$scrypt$ln=16,r=8,p=1$vZdSqnVuba0VIgTAmHPOmQ$gA0DyNxpCxSno3znCvilse4kHR4ILdUE7vqu7l/fZ18' -a scrypt -w rockyou.txt -t 15
```

---

## Uninstallation
**Run the uninstall.sh script**

*Linux*
```bash
sudo bash uninstall.sh
```
*Termux*
```bash
bash uninstall.sh
```
---

## License
This project is licensed under the MIT License
