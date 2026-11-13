# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately to the
maintainers: join the [Discord server](https://bitflash.network/discord) and send a direct
message to a maintainer. Include the version, the platform, what you found and, if you can,
the steps or the input that reproduce it.

A problem that puts coins or the network at risk is fixed in a release before its details are
made public.

## Supported versions

Only the latest release receives fixes. Network upgrades activate on fixed dates, so an old
release can stop following the chain; keep every node current (see the README).

## Scope

In scope: the code in this repository and the release packages built from it. That covers
consensus and block validation, the P2P protocol and peer discovery, Tor handling, the wallet
and its keys, RPC, P2Pool, atomic swaps and the light clients, btfchat, and the build and
signing of releases.

Out of scope: bugs in Tor or XMRig themselves (please report those upstream), attacks that
need control of the user's computer or data directory, and attacks that need a majority of the
network's hashrate.

## Audit

The last full audit, with every finding, every fix and what is deferred and why, is in
[docs/AUDIT.md](docs/AUDIT.md). It is a maintainers' audit done in the open, not one by a
third-party firm. Anyone can rerun it on Linux with `scripts/audit/run-audit.sh`. How to check a
release's signature and rebuild it byte for byte is in
[docs/release-verification.md](docs/release-verification.md).
