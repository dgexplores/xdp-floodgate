# Floodgate

[![ci](https://github.com/wasvaibhav/xdp-floodgate/actions/workflows/ci.yml/badge.svg)](https://github.com/wasvaibhav/xdp-floodgate/actions/workflows/ci.yml)

Kernel-level overload protection with eBPF/XDP: per-IP and node-wide rate
limits enforced in the NIC driver, tunable live, with fleet coordination
planned.

**Status: phase 4 of 6.** An XDP per-source-IP limiter (GCRA token
bucket), SYN limiting, a node-wide PPS cap, per-CPU stats, and a CLI.
Phase 2 adds an IPv4/IPv6 allowlist whose entries use a separate trusted
class of limits. Phases 3 and 4 add a Unix-socket JSON control API,
Prometheus metrics and `status -json`. See
[docs/01-xdp-rate-limiter.md](docs/01-xdp-rate-limiter.md),
[docs/02-allowlist.md](docs/02-allowlist.md),
[docs/03-control-plane.md](docs/03-control-plane.md) and the remaining
phases in [docs/ROADMAP.md](docs/ROADMAP.md).

```sh
make docker-test    # tests, including in-kernel BPF_PROG_RUN
make docker-build   # image: floodgate:dev
```

## Pipeline

Every pull request runs lint, build, unit tests and the in-kernel verifier
tests. `main` only accepts PRs with green checks and the maintainer's
approval. After a merge, the release job waits for a manual Approve/Reject
before publishing `ghcr.io/wasvaibhav/xdp-floodgate`.

## Author

Vaibhav ([@wasvaibhav](https://github.com/wasvaibhav))

Licensing: Go code Apache-2.0, BPF code GPL-2.0 (see SPDX headers).
