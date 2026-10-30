Bitflash Miner
==============

XMRig plus Tor, wired to the Bitflash pool. Nothing to install, nothing to
configure, nothing on the clear net.

  Windows:  mine.cmd YOUR_BTF_ADDRESS
  Linux:    ./mine.sh YOUR_BTF_ADDRESS
  macOS:    ./mine.sh YOUR_BTF_ADDRESS   (Apple silicon, M1 and later)

On macOS, in Terminal, once after unpacking (the download is not signed by
Apple, so macOS holds it until told it is wanted):

  xattr -dr com.apple.quarantine Bitflash-Miner-*-macos-arm64

YOUR_BTF_ADDRESS is a Bitflash payment address: what the Bitflash wallet shows
under Receive, or what `bitflash -newaddress` prints. It is not a .btf node
address. The pool pays out to it; fee 1%. Get the wallet at
https://bitflash.network -- releases are signed.

Add `testnet` after the address to mine the testnet pool with a testnet
address. Anything after that goes to XMRig: `-t 4` uses four threads,
`--help` lists the rest.

What happens when you run it
----------------------------
1. A private Tor client starts (tor/), listening only on 127.0.0.1:9251. It
   keeps its state in tor-data/. It is not the Tor Browser and does not
   touch one if you have it.
2. XMRig starts with that Tor as its SOCKS5 proxy and the pool's onion
   address as the pool. The first connection waits for Tor to bootstrap
   (10-60 s); XMRig retries on its own until it is through.
3. From then on it is an ordinary XMRig session: `new job`, `accepted`,
   hashrate on `h`. Ctrl+C stops both.

The pool is a Bitflash node behind a Tor hidden service, like every node on
this network. There is no server in the middle and no host to switch off.
The address it dials is in mine.cmd / mine.sh; a pool operator can put their
own there.

P2Pool: no pool at all
----------------------
  Windows:  mine.cmd p2pool
  Linux:    ./mine.sh p2pool
  macOS:    ./mine.sh p2pool

Start your own Bitflash node with -p2pool first (the wallet or bitflash-node,
mainnet or -testnet). The node joins the P2Pool share chain over Tor like any
other Bitflash traffic and opens a local stratum on 127.0.0.1:3333 for XMRig.
There is no operator and no fee: every block a P2Pool miner finds pays every
miner in the last window of shares directly in its coinbase, and your node
pays you at an address of its own wallet (or the one given with
-p2poolpayto). No address goes on the command line here. Start the node with
-p2poolport=N and set P2POOL_PORT=N for this script to use another port.

XMRig only talks to 127.0.0.1 in this mode, so it does not use this package's
Tor. Its 1% donation mining (the dev fee XMRig builds in) then connects to the
XMRig donation server directly, not over Tor; the official build does not let
it go below 1%. If that connection matters to you, use the Tor pool mode
above, or build XMRig from source with the donation set to 0.

See docs/p2pool.md in the Bitflash repository for how shares and payouts work.

Expect antivirus noise
----------------------
Windows Defender and most antivirus products flag XMRig because it is what
cryptojacking malware also drops. This is the official XMRig 6.26.0 binary,
unchanged; its SHA-256 is in SHA256SUMS next to this file and matches the
hash published on https://github.com/xmrig/xmrig/releases/tag/v6.26.0. If
your antivirus removes xmrig/xmrig.exe, restore it and add an exclusion for
this folder -- or build XMRig yourself from that repository and drop it in.

WinRing0x64.sys, the driver XMRig's own zip includes, is left out on
purpose: XMRig loads it only when run as administrator, to tweak CPU
registers for a few percent more hashrate, and current Windows blocks it as
a vulnerable driver anyway. XMRig says once that it could not set MSR and
mines normally.

What is inside
--------------
  xmrig/   XMRig 6.26.0, official build (GPLv3, source at github.com/xmrig/xmrig)
  tor/     Tor 15.0.19 client from the Tor Expert Bundle (BSD 3-clause)
  licenses/  the licences of both
  SHA256SUMS, SHA256SUMS.asc  hashes of every file, signed by the Bitflash
           release key 910A 2B4C CA87 9E81 FB4B 2AEA 1D4A 53D3 B78A A4B8

Bitflash proof of work is RandomX with the reference parameters (rx/0) from
PoW v2 on; see docs/pow-v2.md in the Bitflash repository. Before the switch
(mainnet: 2026-09-21 12:00 UTC) the pool refuses XMRig with a message that
names the time.
