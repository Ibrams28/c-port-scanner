# c-port-scanner

A fast, multithreaded TCP port scanner and banner grabber written in C (POSIX) for Linux. Built as a low-level Layer 3/4 network reconnaissance companion to `websec-auditor` (Layer 7 HTTP/OWASP).

## Features

- **POSIX TCP Connect Scan:** Raw BSD socket implementation (`sys/socket.h`) with configurable millisecond send/receive timeouts (`SO_SNDTIMEO` / `SO_RCVTIMEO`).
- **Dynamic Thread Pool:** Concurrent scanning using `pthread` with mutex-synchronized atomic port distribution (`pthread_mutex_t`).
- **DNS & Service Resolution:** Modern thread-safe IPv4 resolution via `getaddrinfo()` and standard service lookup via `getservbyport()`.
- **Active & Passive Banner Grabbing:** Captures spontaneous service banners (SSH, FTP, SMTP) and sends minimal HTTP `HEAD` probes when needed.
- **Structured JSON Export:** Thread-safe result aggregation, port sorting (`qsort`), and RFC-compliant JSON serialization (`-o`).
- **Memory & FD Safe:** Compiled with strict flags (`-Wall -Wextra -Wpedantic`) and verified leak-free under Valgrind.

## Build & Usage

Compile: `make`

Memory check: `make valgrind`

Run scan: `./c-port-scanner -t scanme.nmap.org -s 1 -e 100 -T 50 -w 500 -o scan.json`

## Disclaimer

This tool is intended strictly for educational purposes, network administration, and authorized security auditing.
