#  HashRipper

**HashRipper** is a powerful and fast multi-threaded hash cracking tool written in Python. It supports over 17+ popular hash algorithms including NTLM, MD5, SHA variants, BLAKE2, and more. HashRipper uses a dictionary-based attack and concurrent threading to crack hashes efficiently.

---

##  Features

-  **Multi-threaded** cracking for maximum speed
-  Supports **17+ hash algorithms**
-  Crack hashes from command-line or from file
-  Option to save cracked results to file
-  Simple and clean command-line interface
-  Works on Linux, Termux

---

## Compatibility
- Linux (Debian, RedHat, Arch, etc.)
- Termux (Android)
  
The tool automatically detects the environment and installs itself accordingly.

---

## Supported Hash Algorithms

`md5`

`sha1`

`sha224`

`sha256`

`sha384`

`sha512`

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

`adler_32`

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
**3. Install Dependencies**
```bash
pip3 install -r requirements.txt
```
**4. Run Installer (Linux or Termux)**
```bash
python3 install.py
```
**then type `y` for install**

**5. Run the tool**
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
hashripper --hashfile /home/kali/Desktop/hash.txt -a sha256 -w /home/kali/Desktop/wordlist.txt -o cracked.txt
```
---

## Uninstallation
**Run the install.py script**
```bash
python3 install.py
```
**Then type `n` for uninstall**

---

## License
This project is licensed under the MIT License
