<div align="center">

<img src="docs/logo.png" width="112" height="112" alt="Bitflash logo"/>

# Bitflash

**Bitcoin 0.1.0, revived for the CPU.**<br>
RandomX proof of work, nodes reached only through Tor onion services, no premine.

[Download](https://releases.bitflash.network/) &nbsp;·&nbsp;
[Documentation](https://docs.bitflash.network/) &nbsp;·&nbsp;
[Explorer](https://explorer.bitflash.network/) &nbsp;·&nbsp;
[Testnet faucet](https://faucet.bitflash.network/) &nbsp;·&nbsp;
[Discord](https://discord.gg/kcgeg696YE) &nbsp;·&nbsp;
[X](https://x.com/BTFBitflash)

</div>

> [!IMPORTANT]
> **Every node must run 1.2.32 or newer before 2026-12-25 12:00 UTC**, when rules v4 activate on
> mainnet (testnet: 2026-11-20 12:00 UTC). This applies to wallets, explorers and exchanges as
> well as miners. A node on 1.2.31 or older stops following the chain at the first block that
> uses the new opcodes. See [Network upgrades](#network-upgrades).

> [!NOTE]
> The first exchange listing is being crowdfunded on NonKYC until 2027-02-04: 100 backers are
> needed, and $5 counts as one. Pledges are donations, refunded if the listing does not happen.
> [Campaign page](https://nonkyc.io/listing/campaign/BTF).

## Overview

Bitflash starts from the first release of Bitcoin and keeps its model: a fixed supply of
21 million, a block reward that halves on schedule, and no company, premine or founder
allocation. Two parts are replaced.

- **Proof of work is RandomX**, the memory-hard algorithm Monero uses. It is designed for
  general-purpose processors, so ordinary computers can mine and ASICs and GPUs gain little.
- **Nodes are addressed by key and reached over Tor.** Each node has a `.btf` address derived
  from its public key and publishes a signed descriptor naming the onion service where it can be
  reached. There is no clearnet transport: peers never learn each other's IP address, and a node
  behind NAT or CGNAT needs no port forwarding.

On top of that base the node carries the consensus rules Bitcoin adopted after 0.1.0 (strict
signatures, BIP34, pay-to-script-hash, `OP_CHECKLOCKTIMEVERIFY`) and, from rules v4, relative
lock times, `OP_CHECKTEMPLATEVERIFY` and `OP_CHECKSIGFROMSTACK`. These make possible what the
wallet ships today: vaults, inheritance, atomic swaps with seven other chains, and pooled
mining without a pool operator.

## Download

Packages for every release are at [releases.bitflash.network](https://releases.bitflash.network/)
and on the [GitHub releases page](https://github.com/bitflash-network/bitflash/releases). Tor
is included in every package; nothing else needs to be installed.

| Platform | Package | How to start |
|---|---|---|
| Windows, 64-bit | `Bitflash-<version>-windows-with-tor.zip` | Extract, run `Bitflash.exe` |
| Linux x86_64 | `Bitflash-<version>-x86_64.AppImage` | `chmod +x`, then run it |
| Linux server | `bitflash-node-<version>-x86_64` | `./bitflash-node -nogui -managedtor` |
| macOS 15+, Apple silicon | `Bitflash-<version>-macos-arm64.tar.gz` | From Terminal, see below |
| Mining only | `Bitflash-Miner-<version>-*` | `mine.cmd` or `./mine.sh` |

On macOS the package runs from Terminal:

```bash
xattr -dr com.apple.quarantine Bitflash-*-macos-arm64
cd Bitflash-*-macos-arm64 && ./bitflash-node -managedtor
```

The headless Linux node needs Debian 13, Ubuntu 24.04 or later
(`sudo apt install libsodium23 libdb5.3++ libsqlite3-0 libssl3t64`). On other distributions,
use the AppImage.

Where the download sites are blocked, the same files are served over Tor at
`http://rqzruhh4sm2s3fl6b4mpselkqsaaxebnyptpqhdpt236g57lof7j7sid.onion/`.

### Verifying a download

Each release publishes `SHA256SUMS` and a detached signature, `SHA256SUMS.asc`, made with the
release key `910A 2B4C CA87 9E81 FB4B 2AEA 1D4A 53D3 B78A A4B8`.

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

Release builds are reproducible: the same commit produces the same files byte for byte.
[docs/release-verification.md](docs/release-verification.md) describes how to check the key,
and how to rebuild a release and compare it.

## Wallet

The wallet starts with a twelve-word recovery phrase (BIP39 and BIP32, BIP44 coin type
4346950, registered in [SLIP-0044](https://github.com/satoshilabs/slips/blob/master/slip-0044.md)).
The words are printed once, to the terminal or the window, and never written to `debug.log`.

```bash
bitflash -newphrase                          # create a phrase and show it once
bitflash -restorephrase                      # rebuild a wallet from the phrase (typed on stdin, or -restorephrase=@FILE)
bitflash -backupwallet=/path/to/backup       # write a backup file that opens on its own
```

Keep both the phrase and a file backup. Keys created before a phrase existed, and keys imported
later, are not derived from the words and are restored only from a file. The derivation is
specified in [docs/derivation.md](docs/derivation.md), with test vectors and a standalone
script, so the phrase stays recoverable without this software.

New wallets are stored as a single `wallet.sqlite`. Older Berkeley DB `wallet.dat` files keep
working and can be converted from the window. A `wallet.dat` copied on its own will not open
elsewhere; use `-backupwallet`, or copy the whole data directory with the node stopped. See
[docs/storage.md](docs/storage.md).

Wallet and chain data live in `%APPDATA%\Bitflash` on Windows and `~/.bitflash` on Linux and
macOS. Upgrading replaces only the program; never delete the data directory without a backup.

### Contracts

From the rules v4 activation the wallet can lock coins under conditions enforced by consensus.
Contracts are recorded in `v4contracts.json` beside the wallet; back it up together with the
wallet.

- **Vaults.** Coins can leave only through an unvault transaction that is visible on the chain.
  The spending key can complete the withdrawal after a delay you choose; the recovery key can
  take the coins back at any time before that. See [docs/rules-v4.md](docs/rules-v4.md).
- **Inheritance.** Coins pass to an heir once the owner has been inactive for a chosen period.
  The owner's wallet renews automatically; the heir's package holds no key until it is needed.
  See [docs/inheritance.md](docs/inheritance.md).
- **Batches.** One output now that expands later into a fixed set of payments.

## Mining

| Mode | How |
|---|---|
| Solo | `bitflash -nogui -gen`, or *Options > Mining Mode* in the window |
| P2Pool | `bitflash -nogui -p2pool`, then point XMRig at `127.0.0.1:3333` |
| Bitflash Miner | `mine.cmd YOUR_ADDRESS` on Windows, `./mine.sh YOUR_ADDRESS` on Linux and macOS |
| Your own XMRig | through Tor to the pool onion, see below |

**P2Pool** runs inside the node. Participating nodes keep a share chain, and every block's
coinbase pays the miners of the last 2160 shares in proportion to their work. There is no
operator, no custody and no fee. See [docs/p2pool.md](docs/p2pool.md).

**Bitflash Miner** is the official XMRig release packaged with a Tor client and a launcher. It
mines to the network pool over Tor, with a 1% fee, or to a local P2Pool node with
`mine.cmd p2pool`. Antivirus products commonly flag XMRig; the binary is unmodified, and
[docs/windows-defender.md](docs/windows-defender.md) explains what is reported and why.

To use your own XMRig (5.7.0 or later), run Tor and connect through its SOCKS port:

```bash
xmrig -a rx/0 -x 127.0.0.1:9050 \
  -o mddjuyuctouv62eqdaofvwf4timxxmp72d2ghmc6qp5mdey6f5au56id.onion:8436 \
  -u YOUR_ADDRESS -p x
```

`YOUR_ADDRESS` is a Bitflash payment address, as printed by `-newaddress`, not a `.btf` node
address. Use port 9150 instead of 9050 if Tor Browser provides the proxy.

The node can also run a pool of its own (`-operator`), serving workers on a second port of its
onion service. See [docs/pool-directory.md](docs/pool-directory.md) and
[docs/pow-v2.md](docs/pow-v2.md).

## Trading, messaging and payments

- **Atomic swaps.** BTF for BTC, LTC, BCH, XEC, DOGE, DGB or RVN, without an exchange or an
  intermediary: either both sides are paid or both are refunded. The other chain is reached
  through your own node for that chain, or through a light client built into the wallet that
  verifies every header's proof of work over Tor. Swaps open on mainnet on
  **2026-12-25 12:00 UTC**. See [docs/atomic-swaps.md](docs/atomic-swaps.md).
- **btfchat.** Messages, payments and swap offers between `.btf` addresses. Messages for an
  offline recipient are held, encrypted, by the Bitflash nodes themselves; there is no account
  and no relay. See [docs/btfchat.md](docs/btfchat.md).
- **Payments.** BIP21 payment links and QR codes, replace-by-fee for a stuck payment, and
  invoices for merchants with a signed webhook on payment. See [docs/invoices.md](docs/invoices.md).
- **Block explorer.** *Explorer* in the wallet menu looks up blocks and transactions from the
  node's own files, so no website learns what was looked up.

## Running a node

The desktop app starts its own Tor and creates an onion service on first run. For a server:

```bash
bitflash-node -nogui -managedtor            # node only
bitflash-node -nogui -managedtor -gen       # node and solo miner
bitflash-node -nogui -managedtor -p2pool    # node and P2Pool
```

| Option | Purpose |
|---|---|
| `-datadir=PATH` | Use another data directory |
| `-testnet` | Join the test network (port 18433, separate genesis and data) |
| `-port=N` | P2P port, default 8433 |
| `-managedtor[=PATH]` | Start a Tor process and an onion service for this node |
| `-tor[=HOST:PORT]` | Use an existing Tor SOCKS proxy, default `127.0.0.1:9050` |
| `-torbridges` | Reach Tor through the built-in Snowflake bridges |
| `-torbridge=LINE` | Add an obfs4 or Snowflake bridge of your own |
| `-btfseed=ADDRESS:KEY` | Add a `.btf` bootstrap peer |
| `-help` | List every option |

If a managed Tor reaches no peer within four minutes, the node tries Snowflake, obfs4,
webtunnel and meek bridges in turn and remembers the one that worked (`-notorfallback`
disables this). See [docs/tor.md](docs/tor.md) and
[docs/censored-networks.md](docs/censored-networks.md).

*Menu > Diagnostics* shows peers, sockets, block arrival and mining state, and the same report
is written to `debug.log` every ten minutes. Please include it when reporting a problem.

A minimal systemd unit:

```ini
[Unit]
Description=Bitflash node
After=network-online.target

[Service]
ExecStart=/opt/bitflash/bitflash-node -nogui -managedtor
Restart=always
User=bitflash

[Install]
WantedBy=multi-user.target
```

### Peer discovery

A node's descriptor (its `.btf` address, an encryption key and its current onion) is signed
with the key the address is derived from, so no one can publish a descriptor for an address
they do not control. Nodes find each other through seeds compiled into the binary, a cache of
peers that answered before (`btfpeers.json`) and descriptors exchanged between connected peers.
Nostr is consulted only when none of these has the address. Any node with a stable onion can
serve as a bootstrap seed; it holds no funds and is trusted for nothing.

### Testnet

```bash
bitflash-node -nogui -managedtor -testnet -datadir=/path/to/testnet
```

Give the testnet node its own data directory, so the two networks do not share an onion
service. Test coins are available from the [faucet](https://faucet.bitflash.network/) (10 BTF
per address every six hours), or by mining with `-gen`. Testnet and mainnet addresses look the
same; coins sent to the wrong network cannot be recovered.

## Network upgrades

| Upgrade | Contents | Mainnet activation |
|---|---|---|
| PoW v2 and rules v2 | XMRig-compatible RandomX, strict DER and low-S signatures, BIP34 and BIP30, corrected retarget | Active since 2026-09-21 |
| Rules v3 | Pay-to-script-hash, `OP_CHECKLOCKTIMEVERIFY`, median-time lock-time finality | 2026-11-21 12:00 UTC |
| Rules v4 | BIP68 and `OP_CHECKSEQUENCEVERIFY`, `OP_CHECKTEMPLATEVERIFY`, `OP_CHECKSIGFROMSTACK` | 2026-12-25 12:00 UTC |

Rules v4 activate on testnet on 2026-11-20 12:00 UTC. Each upgrade is specified in
[docs/pow-v2.md](docs/pow-v2.md), [docs/rules-v2.md](docs/rules-v2.md) and
[docs/rules-v4.md](docs/rules-v4.md). A node that has not upgraded before an activation
follows a different chain without warning, so keep every node current.

## Parameters

| | |
|---|---|
| Ticker | BTF |
| Proof of work | RandomX |
| Block time | 2 minutes (target) |
| Difficulty retarget | Every 30 blocks |
| Block reward | 50 BTF, halving every 210,000 blocks (about 292 days) |
| Maximum supply | 21,000,000 BTF |
| Coinbase maturity | 120 blocks |
| P2P port | 8433 (testnet 18433) |
| Premine | None |
| Treasury | Opt-in 2-of-3 multisig that funds exchange listings, public at [bitflash.network/treasury](https://bitflash.network/treasury) ([docs/treasury.md](docs/treasury.md)) |

The halving interval is the same 210,000 blocks as Bitcoin, but at two-minute blocks it comes
roughly every ten months rather than every four years.

## Building from source

```bash
make linux          # Linux: installs dependencies with apt, builds the AppImage
make windows        # Windows, MSYS2 UCRT64: installs dependencies with pacman
make windows-tor    # Windows package with the Tor Expert Bundle
make tests          # unit tests
```

The build fetches and verifies pinned versions of libsecp256k1, RandomX and Tor. Third-party
licenses are listed in [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt) and the full set of
dependencies in [docs/dependencies.md](docs/dependencies.md).

## Documentation

| Topic | Documents |
|---|---|
| Using the wallet | [storage](docs/storage.md), [derivation](docs/derivation.md), [multisig](docs/multisig.md), [inheritance](docs/inheritance.md), [invoices](docs/invoices.md), [RPC reference](docs/rpc.md) |
| Network and privacy | [Tor](docs/tor.md), [censored networks](docs/censored-networks.md), [network hardening](docs/net-hardening.md) |
| Mining | [PoW v2](docs/pow-v2.md), [P2Pool](docs/p2pool.md), [pool directory](docs/pool-directory.md), [mining calculator](docs/mining-calculator.md), [Windows Defender](docs/windows-defender.md) |
| Swaps and chat | [atomic swaps](docs/atomic-swaps.md), [other chains](docs/swaps-multicoin.md), [light clients](docs/light-pow.md), [btfchat](docs/btfchat.md) |
| Consensus | [rules v2](docs/rules-v2.md), [rules v4](docs/rules-v4.md) |
| Auditing | [release verification](docs/release-verification.md), [fair launch](docs/fair-launch.md), [UTXO commitments](docs/utxo-commitment.md), [UTXO proofs](docs/utxo-proofs.md), [treasury](docs/treasury.md) |

The same documents are published at [docs.bitflash.network](https://docs.bitflash.network/).

## Contributing and security

Bug reports and pull requests are welcome on GitHub. Consensus and wallet changes are expected
to come with tests, and are proven on testnet before release. Please report security issues
privately to the maintainers on [Discord](https://discord.gg/kcgeg696YE) rather than in a
public issue.

Bitflash is a young network. Keep your node up to date and do not put in more than you can
afford to lose.

## License

Released under the MIT license, see [LICENSE](LICENSE). Based on Bitcoin 0.1.0 by Satoshi
Nakamoto (2009). The license covers the code; the Bitflash name, logo and domain are not
licensed, see [TRADEMARK.md](TRADEMARK.md).
