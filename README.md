# Diglett

A toy DNS recursive resolver implemented in Rust. It follows the excellent guide by Emil Hernvall to explore how DNS works end‑to‑end while adding a few extra features like TCP support and caching.

Reference guide: [EmilHernvall/dnsguide](https://github.com/EmilHernvall/dnsguide)

### Features
- UDP and TCP DNS servers (listening on 2053/UDP and 2054/TCP)
- Recursive resolution starting from a root server
- Response caching with TTL awareness
- Async concurrency via Tokio
- Record parsing and encoding for A, AAAA, NS, CNAME, MX, SOA, and UNKNOWN
- Basic RCode handling (NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED)

### Non‑Goals / Current Limitations
- EDNS(0) and DNSSEC are not implemented yet
- Only a single root server is used as a starting point (hard‑coded)
- Minimal logging (println! based)
- Limited configuration (ports, root server) via code constants

## Getting Started

### Prerequisites
- Rust (stable) and Cargo installed

### Build
```bash
cargo build --release
```

### Run
```bash
cargo run --release
```
This starts:
- UDP server on 0.0.0.0:2053
- TCP server on 0.0.0.0:2054

### Try it with dig
- UDP query:
```bash
dig @127.0.0.1 -p 2053 example.com A
```
- TCP query:
```bash
dig +tcp @127.0.0.1 -p 2054 example.com A
```

## Configuration
Currently, listening addresses and the initial root nameserver are hard‑coded in `src/main.rs`:
- Ports: `2053` (UDP) and `2054` (TCP)
- Root NS: `198.41.0.4`

You can change these defaults directly in `main()` or in `recursive_lookup()` and rebuild.

## Project Structure
- `src/main.rs`: UDP and TCP server entrypoints, request handling, and recursive resolution orchestration
- `src/lib.rs`: Core DNS types (header, question, records, packet), read/write/encode/decode logic
- `src/buffer.rs`: Read/write buffer abstractions (`ArrayBuffer` for UDP, `VecBuffer` for TCP) and qname compression
- `src/cache.rs`: Simple TTL‑aware in‑memory cache with `Arc<Mutex<...>>`
- `Cargo.toml`: Crate definition and dependencies (`eyre`, `tokio`, `futures`)

### How recursive resolution works
`recursive_lookup()` starts from a root NS, sends a query (UDP or TCP depending on server), and iteratively follows referrals:
1. If answers contain the requested records, return them
2. If NXDOMAIN, return immediately
3. If an additional A record for the next NS is present, use it
4. Otherwise, resolve that NS name to an A record and continue

Results are cached based on TTL, and subsequent queries will use the cache when valid entries are present.

## Roadmap
- [x] Add concurrency to the server using async/await
- [x] Add TCP support
- [x] Add caching support
- [ ] Implement EDNS(0) (OPT record, larger UDP payloads)
- [ ] Implement DNSSEC validation (DNSKEY/DS/RRSIG chain)
- [ ] Improve caching structure and TTL handling (cleanup, LRU/eviction)
- [ ] Use cache to shortcut NS resolution (nearest A record)
- [ ] Fallback to TCP on truncation automatically
- [ ] Make ports, addresses, and root hints configurable (env/flags)
- [ ] Update to Rust 2021 edition and Tokio 1.x
- [ ] Replace println! with structured logging/tracing
- [ ] Unit tests for buffer and record encode/decode
- [ ] Integration tests for recursive resolution
- [ ] CLI client for direct queries
- [ ] Dockerfile and Makefile for containerized dev
- [ ] GitHub Actions CI (fmt, clippy, test)
- [ ] Use full root hints set and randomize selection
- [ ] Additional RR types: TXT, SRV, CAA, PTR
- [ ] Graceful shutdown and signal handling
- [ ] Security hardening: randomize query IDs and ephemeral UDP port usage
- [ ] Negative caching per RFC 2308
- [ ] Metrics/Prometheus endpoint

## Acknowledgements
Inspired by and based on the excellent tutorial by Emil Hernvall: `https://github.com/EmilHernvall/dnsguide`.