# Auditing Bitflash

What checks the code, how to run each check yourself, and what the last full
run found. Everything here is free software or free for public repositories,
and none of it needs an account.

## Where each check runs

| when | what | where |
|---|---|---|
| every push and pull request | Linux and Windows self-test suites, Python tool regressions, short fuzz runs of three targets | `.github/workflows/ci.yml` |
| every pull request into `main` | CodeQL (C++, Python, workflows); ClusterFuzzLite, ten minutes on the code the change touches | `.github/workflows/codeql.yml`, `.github/workflows/cflite.yml` |
| every night (GitHub) | ClusterFuzzLite, one hour per sanitizer, corpus kept between runs | `.github/workflows/cflite.yml` |
| every Monday (GitHub) | CodeQL over `main` | `.github/workflows/codeql.yml` |
| before a release, or by hand | the full pass below: every tool, every sanitizer, three fuzzing engines | `scripts/audit/run-audit.sh` |

CodeQL and ClusterFuzzLite report into the repository's **Security** tab
(code scanning alerts). The full pass writes to a directory of its own; read
`SUMMARY.txt` there first.

## The full pass

```bash
scripts/audit/run-audit.sh                  # every phase, in order
scripts/audit/run-audit.sh static asan      # some phases
OUT=/srv/audit FUZZ_SECS=7200 J=6 scripts/audit/run-audit.sh fuzz
```

It needs a Linux machine with the normal build dependencies (`make
deps-linux`) and the tools below. On Debian 13 all but four come from the
distribution:

```bash
apt-get install clang clang-tidy clang-tools cppcheck gitleaks afl++ valgrind \
    heaptrack ltrace strace llvm-19 lcov flawfinder diffoscope-minimal reprotest \
    iwyu strip-nondeterminism tcpdump python3-venv
```

The four that do not, each pinned and checked against its publisher's
checksum before it is installed:

| tool | how | why not Debian |
|---|---|---|
| honggfuzz | build tag `2.6` from https://github.com/google/honggfuzz (`make && make install`) | dropped from Debian 13 |
| Trivy | release tarball + `trivy_<v>_checksums.txt`, https://github.com/aquasecurity/trivy/releases | not packaged |
| OSV-Scanner | release binary + `osv-scanner_SHA256SUMS`, https://github.com/google/osv-scanner/releases | not packaged |
| Semgrep | `pip install semgrep==<v>` in a venv | not packaged |

Pick versions at least two weeks old: a compromised release is usually found
and pulled within days.

Nothing in the pass touches a real data directory. `HOME` points at a scratch
folder for the whole run, and the fuzz harnesses each make a private temporary
data directory before their first input (`src/fuzz_datadir.h`), so a machine
that also runs a node can run the audit.

## The tools

### Secrets and dependencies (`secrets`, `deps`)

- **Gitleaks** reads every commit for keys, tokens and passwords.
- **Trivy** (`trivy fs`) reads the tree for secrets, misconfigured container
  and infrastructure files, and manifests with known-vulnerable versions.
  `trivy rootfs` then lists advisories for the system libraries a Linux build
  links (OpenSSL, Berkeley DB, libsodium, SQLite, zlib, glibc, Tor) as
  installed on the auditing machine.
- **OSV** (`scripts/audit/osv-query.py`): the tree has no package manifest for
  scanners to read, so the commits it pins (libsecp256k1, RandomX, the vendored
  DigiByte and Ravencoin proof-of-work code) are sent to https://osv.dev one by
  one. Only public commit hashes leave the machine.

### Static analysis (`static`)

- **cppcheck**: undefined behaviour, out-of-bounds access, uninitialised
  members, misuse of the standard library.
- **flawfinder**: calls with a history (`system`, `strcpy`, `chmod` races,
  format strings); levels 4 and 5 only.
- **Semgrep**: the `p/c` and `p/secrets` rule packs.
- **clang-tidy**: `bugprone-*`, `cert-*` and `clang-analyzer-*` over the files
  that parse network or disk input, hold coins, or decide the chain.
- **Clang Static Analyzer** (`scan-build`): path-sensitive analysis of the
  whole node build (null dereferences, leaks, use after free, dead stores).
- **CodeQL** (on GitHub): data-flow queries, `security-extended` suite.

### Running the code under instruments (`asan`, `tsan`, `valgrind`, `heap`)

Every self-test that `make tests` runs, each in four builds:

- **AddressSanitizer + UndefinedBehaviorSanitizer + LeakSanitizer**: out-of-bounds
  and use-after-free accesses, integer overflow, misaligned and null access,
  leaks at exit.
- **ThreadSanitizer**: data races and lock-order inversions.
- **Valgrind memcheck**: the same class of memory errors on an uninstrumented
  build, including in the libraries the sanitizers cannot see into.
- **heaptrack**: peak memory and leaks of the heaviest self-tests.

A self-test passes only if it exits 0 *and* its log has no sanitizer report.

### Fuzzing (`fuzz`, and ClusterFuzzLite on GitHub)

Four harnesses in `src/`:

| target | what it feeds |
|---|---|
| `fuzz-net-message` | raw bytes into the P2P receive buffer of a peer, through `ProcessMessages()` |
| `fuzz-script` | one script through the parser, the standard-form extractors and `EvalScript` |
| `fuzz-sigcheck` | signatures and keys into OpenSSL and libsecp256k1 side by side; any disagreement is a crash |
| `fuzz-light-pow` | headers and histories into the DigiByte and Ravencoin difficulty and proof-of-work checks |

Each runs under **libFuzzer**, **AFL++** and **honggfuzz** in turn, all three
with AddressSanitizer and UndefinedBehaviorSanitizer. They share one corpus
per target: what one engine finds is minimised into the corpus
(`libFuzzer -merge=1`) before the next starts. Crashes land in
`crashes/<engine>-<target>-*`; replay one with `./<target> <file>`.

### Coverage (`cov`)

**llvm-cov** over the self-tests, and over each fuzz corpus replayed through a
coverage build. Low numbers point at the code no test reaches.

### Reproducible builds (`repro`)

**reprotest** builds the node twice, varying time, time zone, locale, umask,
environment and build path, and compares the binaries; on any difference
**diffoscope** shows where. Release builds have their own reproducibility
check (`docs/release-verification.md`).

## Not used, and why

| tool | reason |
|---|---|
| PVS-Studio, Snyk | need an account |
| MemorySanitizer | every library linked (OpenSSL, Berkeley DB, libsodium, SQLite, the C++ library) would have to be rebuilt with it; AddressSanitizer, Valgrind and the fuzzers cover the same bugs here |
| nmap, testssl.sh | the node speaks only through Tor onion services and has no TLS endpoint of its own to scan |
| tcpdump, tshark, scapy | installed for debugging; the P2P protocol is fuzzed at the parser instead of over a wire |
| Threat Dragon, threatspec | a threat model is a document, not a scan; the network's is spread over `docs/net-hardening.md`, `docs/tor.md` and `docs/rendezvous.md` |
| cosign, in-toto | come with signed reproducible release builds; releases are signed with the release key today (`docs/release-verification.md`) |
| bug bounty platforms | need an account and funds; reports go to the maintainers as described in the README |

## Last full run

RESULTS_PLACEHOLDER
