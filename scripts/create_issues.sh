#!/usr/bin/env bash
set -euo pipefail

# Create GitHub issues for roadmap items using GitHub REST API v3.
# Requirements:
#  - GITHUB_TOKEN environment variable with repo:issues scope
#  - A git remote named "origin" pointing to github.com

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required. Please install jq and re-run." >&2
  exit 1
fi

if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "GITHUB_TOKEN is not set. Export GITHUB_TOKEN and re-run." >&2
  exit 1
fi

origin_url=$(git remote get-url origin 2>/dev/null || true)
if [[ -z "$origin_url" ]]; then
  echo "No git remote named 'origin' found." >&2
  exit 1
fi

# Normalize origin URL to https form
origin_url=${origin_url%.git}
if [[ "$origin_url" =~ ^git@github.com:(.*)/(.*)$ ]]; then
  owner="${BASH_REMATCH[1]}"
  repo="${BASH_REMATCH[2]}"
elif [[ "$origin_url" =~ ^https?://([^/]+)/([^/]+)/([^/]+)$ ]]; then
  host="${BASH_REMATCH[1]}"
  owner="${BASH_REMATCH[2]}"
  repo="${BASH_REMATCH[3]}"
else
  echo "Could not parse origin URL: $origin_url" >&2
  exit 1
fi

if [[ "$host" != "github.com" && "$host" != "www.github.com" ]]; then
  echo "Origin host is not github.com: $host" >&2
  exit 1
fi

api="https://api.github.com/repos/${owner}/${repo}/issues"

create_issue() {
  local title="$1"
  local body="$2"
  local labels="$3" # comma-separated

  payload=$(jq -n --arg title "$title" --arg body "$body" --arg labels_csv "$labels" '
    {
      title: $title,
      body: $body,
      labels: ($labels_csv | split(",") | map(select(. != "")))
    }
  ')

  curl -sfSL -H "Authorization: token ${GITHUB_TOKEN}" \
       -H "Accept: application/vnd.github+json" \
       -d "$payload" "$api" >/dev/null
  echo "Created: $title"
}

readme_roadmap="/workspace/README.md"

issues=(
  "Implement EDNS(0)|Support OPT record, larger UDP payloads, and negotiation.|enhancement"
  "Implement DNSSEC validation|Add DNSKEY/DS/RRSIG support and validation chain.|security,enhancement"
  "Improve caching and TTL handling|Eviction, cleanup, and strict TTL policy.|enhancement"
  "Use cache to shortcut NS resolution|Nearest A record lookup for NS hosts.|performance,enhancement"
  "Fallback to TCP on truncation|Auto-detect truncated UDP and retry over TCP.|bug,enhancement"
  "Externalize configuration|Ports, root hints, and addresses via env/flags.|enhancement"
  "Update to Rust 2021 and Tokio 1.x|Modernize toolchain and APIs.|maintenance"
  "Structured logging|Adopt tracing/log and include request IDs.|observability"
  "Add unit and integration tests|Buffers, records, recursion behavior.|testing"
  "CLI client|Direct DNS queries over UDP/TCP from CLI.|feature"
  "Containerization and tooling|Dockerfile and Makefile targets.|devops"
  "CI pipeline|GitHub Actions for fmt, clippy, tests.|ci"
  "Root hints improvements|Full root set and randomized selection.|enhancement"
  "Additional RR types|TXT, SRV, CAA, PTR parsing/encoding.|feature"
  "Graceful shutdown and signals|Handle SIGINT/SIGTERM and cleanup.|maintenance"
  "Security hardening|Randomize query IDs and UDP source ports.|security"
  "Negative caching (RFC 2308)|Cache NXDOMAIN and NODATA with TTLs.|feature"
  "Metrics/observability|Prometheus metrics for traffic and latency.|observability"
)

for entry in "${issues[@]}"; do
  IFS='|' read -r title body labels <<<"$entry"
  create_issue "$title" "$body" "$labels"
done

echo "All issues created (if not already present)."
