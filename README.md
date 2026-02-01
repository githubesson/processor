# ulp-parser

a fast credential log parser written in rust. handles the messy formats you find in stealer logs - the ones with `url:username:password` lines, block-style password files, nested archives, all that stuff.

## what it does

- extracts archives (zip, 7z, rar, tar.gz, etc) recursively - archives inside archives, up to 10 levels deep
- finds password files (`passwords.txt`, `all passwords.txt`, etc)
- parses both line-based (`url:user:pass`) and block-based formats
- deduplicates credentials
- outputs json or plain text

## install

```
cargo build --release
```

the binary ends up in `target/release/ulp-parser`

on windows, you should drop `7z.exe` (from here: https://7-zip.org/download.html "7-Zip Extra: standalone console version..."; you want to grab the `7za.exe` from the archive and rename it to `7z.exe`) next to the binary and it'll use that automatically. handy for portable setups.

## usage

### extract an archive

```
ulp-parser extract archive.zip
```

this will:
1. extract the archive (and any nested archives inside)
2. find all password files
3. parse them
4. output `unique.json` and `combined.json`

options:
- `-o <dir>` - output directory (default: same folder as the binary)
- `-p <password>` - archive password
- `-j <n>` - number of threads (default: cpu count)
- `-s` - print stats
- `--keep-archive` - don't delete the archive after extraction
- `--txt` - also output `unique.txt` with `url:user:pass` lines

### parse existing txt files

```
ulp-parser parse file.txt -o ./output
```

or a whole directory:

```
ulp-parser parse ./logs/ -o ./output -s
```

filtering:
- `-f <pattern>` - regex filter on urls
- `-d <domain>` - only keep specific domains
- `--exclude-domain <domain>` - exclude domains

### other commands

```
ulp-parser validate ./logs/     # check files without writing output
ulp-parser info file.ulpb       # show binary file info
ulp-parser to-text file.ulpb    # convert binary back to text
```

## how it works

### parsing formats

the parser handles two main formats:

**line format** - the classic `url:user:pass` style:
```
https://example.com/login:user@email.com:password123
https://site.com:8080/auth:admin:secretpass
```

the tricky part is figuring out where the url ends and credentials begin. the parser looks for `://` first, then finds the right colon by checking for paths (`/`), ports (`:8080`), and `@` symbols in android-style urls.

**block format** - the labeled style from browser stealers:
```
URL: https://example.com
Username: user@email.com
Password: mypassword
=======================
URL: https://other.com
Username: admin
Password: secret
```

the block parser normalizes keys (strips spaces, dashes, underscores) and handles variations like `User Name`, `user-name`, `LOGIN`, etc. it auto-detects whether blocks end after url, username, or password fields by analyzing the whole file first.

### extraction flow

1. run `7z x` on the input archive
2. scan for more archives in the extracted files
3. extract those too (repeat up to 10 levels)
4. delete successfully extracted archives to save space
5. find all password files by name
6. figure out the "log root" directories - usually the level with ip addresses or user identifiers
7. assign a uuid to each log root
8. parse all password files in parallel using rayon
9. deduplicate by (url, username, password) tuple
10. write json output

### output format

```json
[
  {
    "url": "https://example.com",
    "username": "user@example.com",
    "password": "password123",
    "uuid": "550e8400-e29b-41d4-a716-446655440000",
    "dir": "./192.168.1.100"
  }
]
```

- `uuid` - identifies which log root this credential came from
- `dir` - relative path to the log root

### binary format

there's also a compact binary format (`.ulpb`) for the parse command:
- 8-byte magic header
- 4-byte record count
- records stored as length-prefixed byte strings
- ~40% smaller than text

### threading

both extraction and parsing are parallelized:
- extraction uses 7z's built-in threading
- file parsing uses rayon with configurable thread count

for large archives with thousands of password files, this makes a big difference.

## dependencies

- `7z` - must be installed and in PATH (or next to the exe on windows)
- on linux, `unrar` is used for rar files if available

## supported archive formats

whatever 7z supports: zip, 7z, rar, tar, tar.gz, tar.bz2, tar.xz, etc.

## license

mit
