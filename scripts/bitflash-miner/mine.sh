#!/bin/sh
# Bitflash Miner: XMRig over Tor, straight to the pool's hidden service.
#   ./mine.sh YOUR_BTF_ADDRESS            mainnet
#   ./mine.sh YOUR_BTF_ADDRESS testnet    testnet pool (testnet address!)
#   ./mine.sh p2pool                      P2Pool: your own node, no pool at all
# Anything after those is passed to XMRig, e.g. -t 4 to use 4 threads.
cd "$(dirname "$0")" || exit 1

POOL=mddjuyuctouv62eqdaofvwf4timxxmp72d2ghmc6qp5mdey6f5au56id.onion:8436
SOCKS=127.0.0.1:9251

if [ -z "$1" ]; then
    cat <<EOF

  usage: ./mine.sh YOUR_BTF_ADDRESS [testnet] [xmrig options]
         ./mine.sh p2pool [xmrig options]

  YOUR_BTF_ADDRESS is a Bitflash payment address -- the kind the Bitflash
  wallet shows under Receive, or -newaddress prints. Not a .btf address.
  The pool pays out to it. Fee 1%.

  p2pool: mine through your own Bitflash node started with -p2pool. No pool,
  no operator, no fee: every block pays its miners directly, and your node
  pays you at an address of its own wallet. See README.txt.

EOF
    exit 1
fi

# P2Pool: XMRig talks to this machine's own node; there is nobody to reach
# over Tor. P2POOL_PORT if the node was started with another -p2poolport.
if [ "$1" = "p2pool" ]; then
    shift
    PORT=${P2POOL_PORT:-3333}
    echo "P2Pool: mining through your own node at 127.0.0.1:$PORT"
    echo "(start it first: bitflash-node -p2pool, or the wallet with -p2pool)"
    echo
    exec ./xmrig/xmrig -a rx/0 -o "127.0.0.1:$PORT" -u p2pool -p x --retries=100000 --retry-pause=5 "$@"
fi
ADDR=$1; shift
if [ "$1" = "testnet" ]; then
    POOL=vocwzaqll3vzuvs4nkva5fxh6q5odlokkqvfc2uvhcjtmjlygae5l4id.onion:18438
    shift
fi

mkdir -p tor-data
chmod 700 tor-data
echo "Starting Tor (own instance, SOCKS on $SOCKS)..."
# The Expert Bundle's tor has no RUNPATH; it needs the libevent/libssl/libcrypto
# shipped in tor/ ahead of the system's, or it dies with "undefined symbol:
# evutil_secure_rng_add_bytes" (exit 127) on Fedora 44 / Ubuntu 26.04.
# On macOS the loader reads DYLD_LIBRARY_PATH instead.
if [ "$(uname -s)" = "Darwin" ]; then
    DYLD_LIBRARY_PATH="$PWD/tor${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" ./tor/tor --SocksPort "$SOCKS" --DataDirectory tor-data --Log "notice file tor-data/tor.log" --ClientOnly 1 >/dev/null 2>&1 &
else
    LD_LIBRARY_PATH="$PWD/tor${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ./tor/tor --SocksPort "$SOCKS" --DataDirectory tor-data --Log "notice file tor-data/tor.log" --ClientOnly 1 >/dev/null 2>&1 &
fi
TORPID=$!
echo "Tor bootstraps in 10-60 s; XMRig retries until it is through."
echo "Pool: $POOL"
echo

./xmrig/xmrig -a rx/0 -x "$SOCKS" -o "$POOL" -u "$ADDR" -p x --retries=100000 --retry-pause=5 "$@" &
XMPID=$!
# Whatever ends this script -- Ctrl+C, a kill, XMRig exiting -- takes both
# processes with it, and only these two.
trap 'kill $XMPID $TORPID 2>/dev/null' EXIT INT TERM
wait $XMPID
