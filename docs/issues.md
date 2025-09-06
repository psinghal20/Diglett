# Project Roadmap and Issues

This document tracks planned enhancements and outstanding work items. Each item below is intended to be mirrored as a GitHub issue. Use `scripts/create_issues.sh` to create them automatically if you have a `GITHUB_TOKEN` and a GitHub remote configured.

Note: Completed items (already implemented) are not listed here.

## Implement EDNS(0)
- Enable OPT pseudo-record support
- Support larger UDP payload sizes and proper fallback behavior
- Validate EDNS presence and negotiate sizes

## Implement DNSSEC validation
- Add support for DNSKEY, DS, and RRSIG records
- Validate chains of trust up to a configured trust anchor
- Surface SERVFAIL when validation fails

## Improve caching and TTL handling
- Introduce eviction policy (e.g., LRU) and background cleanup
- Store authoritative/additional separately; respect TTLs strictly
- Avoid stale entries; handle cache poisoning concerns

## Use cache to shortcut NS resolution
- Implement nearest A record lookup for NS hosts
- Use cached referrals to reduce upstream queries

## Fallback to TCP on truncation
- Detect `truncated_msg` and retry over TCP automatically
- Ensure idempotent behavior and consistent response assembly

## Make configuration external
- Expose ports, bind addresses, and root hints via env vars/flags
- Use a config file option for more complex settings

## Update toolchain and dependencies
- Migrate to Rust 2021 edition
- Upgrade to Tokio 1.x and adjust APIs accordingly

## Structured logging
- Replace println! with `tracing` or `log` + `env_logger`
- Include request IDs and timing information

## Testing
- Unit tests for `buffer` and record encode/decode paths
- Integration tests for recursive resolution and referral logic

## CLI client
- Provide a simple CLI for direct queries (A/AAAA/NS/CNAME/MX/SOA)
- Support UDP/TCP switches and timeouts

## Containerization and tooling
- Add Dockerfile and Makefile targets
- Provide `make run`, `make test`, `make lint`

## CI pipeline
- GitHub Actions: fmt, clippy, tests on PRs
- Optionally cache Cargo builds for speed

## Root hints improvements
- Use the full set of root servers
- Randomize starting root to spread load

## Additional RR types
- TXT, SRV, CAA, PTR parsing and serialization

## Graceful shutdown and signals
- Handle SIGINT/SIGTERM
- Ensure sockets close cleanly and tasks are awaited

## Security hardening
- Randomize query IDs per request
- Avoid fixed UDP source port; consider socket per request or OS assignment

## Negative caching (RFC 2308)
- Cache NXDOMAIN and NODATA responses with appropriate TTLs

## Metrics/observability
- Expose Prometheus metrics (queries, cache hits/misses, latency)