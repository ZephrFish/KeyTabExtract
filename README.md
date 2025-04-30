# KeyTabExtract

## Description
KeyTabExtract is a utility to help extract valuable information from Kerberos .keytab files, which may be used to authenticate Linux boxes to Kerberos. The script extracts information such as the realm, Service Principal, Encryption Type, and hashes (NTLM, AES-128, AES-256) with timestamps.

## Features

- Extract RC4-HMAC (NTLM), AES128, and AES256 hashes
- Display all keys sorted by timestamp (newest first)
- Support for multiple keytab versions (0501, 0502)
- Hash verification to ensure valid output
- Colourised output for better readability
- Batch processing of multiple keytab files
- Multiple hash format options (plain, hashcat, john)
- Comprehensive logging

## Requirements

- Python 3.6 or higher
- colorama (optional, for coloured output)

## Installation

### Option 1: Install dependencies only

```bash
pip install -r requirements.txt
```

## Usage

```
usage: keytabextract.py [-h] (-d DIRECTORY | [keytab]) [-o OUTPUT] [-v]
                        [-f {plain,hashcat,john}] [--no-colour] [--log LOG]
                        [--log-level {DEBUG,INFO,WARNING,ERROR}] [--dry-run]

KeyTabExtract: Extract hashes from Kerberos keytab files with timestamps

positional arguments:
  keytab                 Path to the keytab file

optional arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        Process all .keytab files in the specified directory
  -o OUTPUT, --output OUTPUT
                        Save results to the specified file or directory (for batch mode)
  -v, --verbose         Enable verbose output
  -f {plain,hashcat,john}, --format {plain,hashcat,john}
                        Output format for hashes (plain, hashcat, or john)
  --no-colour           Disable coloured output
  --log LOG             Log file path
  --log-level {DEBUG,INFO,WARNING,ERROR}
                        Set logging level
  --dry-run             Analyse the keytab file without extracting hashes
```

## Examples

### Basic usage

```bash
./keytabextract.py service.keytab
```

### Save results to a file

```bash
./keytabextract.py -o hashes.txt service.keytab
```

### Format hashes for hashcat

```bash
./keytabextract.py -f hashcat service.keytab
```

### Process all keytab files in a directory

```bash
./keytabextract.py -d /path/to/keytabs -o output_dir
```

### Enable verbose output and logging

```bash
./keytabextract.py -v --log keytab.log --log-level DEBUG service.keytab
```

## Output Format

The tool displays information in a hierarchical format:

```
=== KeyTabExtract Results ===
File: service.keytab
Version: 0502

Realm: EXAMPLE.COM
  Service Principal: HTTP/server.example.com
    Timestamp: 2023-04-30 15:45:23 (KVNO: 3)
      NTLM: 8846f7eaee8fb117ad06bdd830b7586c
      AES-128: 3f5b9e2f3ad16b2e11ca4d90d87d6a48
    Timestamp: 2023-01-15 09:12:05 (KVNO: 2)
      NTLM: 2d8f65e0ce5f2d7c2d8f65e0ce5f2d7c
```

