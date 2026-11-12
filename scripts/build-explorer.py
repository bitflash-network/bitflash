#!/usr/bin/env python3
"""Build a static Bitflash block explorer from local blk*.dat files."""

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

import bitflash_chain as chain


ADDRESS_VERSION = 25
SCRIPT_ADDRESS_VERSION = 28
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload, version=ADDRESS_VERSION):
    v = bytes([version]) + payload
    v += chain.sha256d(v)[:4]
    n = int.from_bytes(v, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = B58[r] + s
    for byte in v:
        if byte == 0:
            s = "1" + s
        else:
            break
    return s


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


# The treasury's output script, hex, when given with --treasury: its outputs
# are labelled so a reader can tell a share to the fund from any other multisig.
TREASURY_HEX = None
TESTNET = False


def spk_info(script_hex):
    try:
        spk = bytes.fromhex(script_hex)
    except ValueError:
        return {"type": "malformed", "hex": script_hex[:80]}
    if TREASURY_HEX and script_hex == TREASURY_HEX:
        return {"type": "treasury", "address": "treasury"}
    if (
        len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xA9
        and spk[2] == 0x14 and spk[23] == 0x88 and spk[24] == 0xAC
    ):
        return {"type": "p2pkh", "address": b58check(spk[3:23])}
    # A swap's contract, on this chain, is one of these.
    if len(spk) == 23 and spk[0] == 0xA9 and spk[1] == 0x14 and spk[22] == 0x87:
        return {"type": "p2sh", "address": b58check(spk[2:22], SCRIPT_ADDRESS_VERSION)}
    if spk[:1] == b"\x6a":
        return {"type": "data"}
    if len(spk) >= 35 and spk[-1] == 0xAC:
        if spk[0] == 0x41 and len(spk) == 67:
            pk = spk[1:66]
            return {"type": "p2pk", "pubkey": pk.hex(), "address": b58check(hash160(pk))}
        if spk[0] == 0x21 and len(spk) == 35:
            pk = spk[1:34]
            return {"type": "p2pk", "pubkey": pk.hex(), "address": b58check(hash160(pk))}
    # bare m-of-n multisig: m, n pushes of 33 or 65 bytes, n, OP_CHECKMULTISIG
    if len(spk) >= 37 and spk[-1] == 0xAE and 0x51 <= spk[0] <= 0x60 and 0x51 <= spk[-2] <= 0x60:
        m, n, i, keys = spk[0] - 0x50, spk[-2] - 0x50, 1, 0
        while i < len(spk) - 2 and spk[i] in (33, 65):
            i += 1 + spk[i]
            keys += 1
        if i == len(spk) - 2 and keys == n and 1 <= m <= n:
            return {"type": "multisig", "address": "multisig %d-of-%d" % (m, n)}
    return {"type": "other", "hex": script_hex[:80]}


def explorer_tx(tx):
    vin = []
    for txin in tx["vin"]:
        coinbase = (
            txin["prevout_hash"] == "0" * 64
            and txin["prevout_n"] == 0xFFFFFFFF
        )
        vin.append({
            "coinbase": coinbase,
            "prev": None if coinbase else txin["prevout_hash"],
            "vout": None if coinbase else txin["prevout_n"],
        })
    vout = []
    for out in tx["vout"]:
        vout.append(dict({"value": out["value_satoshis"]}, **spk_info(out["script_pub_key_hex"])))
    return {"txid": tx["txid"], "vin": vin, "vout": vout, "size": len(chain.ser_tx(tx))}


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--datadir", help="Bitflash data directory containing blk*.dat")
    ap.add_argument("--testnet", action="store_true",
                    help="the blocks are the public test chain's")
    ap.add_argument("--max-blocks", type=int, default=0,
                    help="number of blocks to scan; 0 means all block files")
    ap.add_argument("--treasury", default=None,
                    help="the treasury output script, hex: its outputs are labelled 'treasury'")
    ap.add_argument("paths", nargs="+",
                    help="with --datadir: <out-dir>; otherwise: <blk*.dat>... <out-dir>")
    args = ap.parse_args(argv)
    global TREASURY_HEX, TESTNET
    TREASURY_HEX = args.treasury.lower() if args.treasury else None
    TESTNET = args.testnet
    if TESTNET:
        chain.use_testnet()
    if args.datadir:
        if len(args.paths) != 1:
            raise SystemExit("usage with --datadir: build-explorer.py --datadir DATADIR <out-dir>")
        args.block_files = None
        args.out_dir = args.paths[0]
    else:
        if len(args.paths) < 2:
            raise SystemExit("usage: build-explorer.py <blk*.dat>... <out-dir>")
        args.block_files = args.paths[:-1]
        args.out_dir = args.paths[-1]
    return args


def load_blocks(args):
    if args.datadir:
        return chain.read_blocks(args.datadir, args.max_blocks)
    return chain.read_blocks_from_files(args.block_files, args.max_blocks)


# Consensus target spacing, seconds. Here only to be shown next to the measured
# interval, so a reader can see how far the chain is from where it aims.
TARGET_SPACING = 120

# How many blocks the hashrate estimate looks back over. Long enough to survive
# one lucky or one slow block, short enough to still be about now: at two
# minutes a block this is a little under five hours.
HASHRATE_WINDOW = 144


def target_from_bits(bits):
    """The compact form, expanded. Same rule as CBigNum::SetCompact."""
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def network_estimate(blocks):
    """Estimated network hashrate.

    The first question anyone asks before mining a coin is how much hashrate is
    already pointed at it, and this explorer could not answer it. It can: the
    answer is in the blocks it already parses.

    Expected hashes per block is 2^256 / (target+1) -- a property of the target
    alone, true for any hash-against-a-target proof of work, RandomX included.
    Divide by how many seconds a block actually took and the result is hashes
    per second.

    It is an estimate and it is labelled as one. Finding a block is a Poisson
    process: a quiet half hour and a lucky one both move this number without
    anybody's hardware changing.
    """
    if not blocks:
        return None
    tip = blocks[-1]
    bits = int(tip["bits"], 16)
    target = target_from_bits(bits)
    if target <= 0:
        return None

    out = {
        "bits": "0x%08x" % bits,
        "targetSpacing": TARGET_SPACING,
        "hashesPerBlock": (1 << 256) // (target + 1),
    }

    n = min(HASHRATE_WINDOW, len(blocks) - 1)
    if n > 0:
        elapsed = tip["time"] - blocks[-1 - n]["time"]
        # A block timestamp is the miner's claim, not a clock, and the rules
        # only order them loosely. A window that comes out zero or negative
        # says nothing about hashrate, so this says nothing rather than
        # printing a number that would be read as one.
        if elapsed > 0:
            # Each block's own target, not the tip's repeated n times.
            #
            # Difficulty retargets every 30 blocks here, clamped to 4x and 1/4,
            # so a 144-block window can span five of them. Charging the whole
            # window at today's target would credit work to blocks that were
            # never that hard -- overstating the number after a rise and
            # understating it after a fall, which is exactly when somebody is
            # most likely to be reading it. Summing the real work per block is
            # what chainwork is, and what getnetworkhashps does with it.
            total = 0
            for b in blocks[-n:]:
                t = target_from_bits(int(b["bits"], 16))
                if t <= 0:
                    total = 0
                    break
                total += (1 << 256) // (t + 1)
            if total > 0:
                out["window"] = n
                out["intervalSec"] = elapsed / float(n)
                out["hashrate"] = total / float(elapsed)
    return out


def build_explorer(raw_blocks, out_dir):
    try:
        blocks = chain.select_main_chain(raw_blocks)
    except chain.ParseError as e:
        raise SystemExit(str(e))
    out = Path(out_dir)
    # Wipe any previous block files so a change in layout (or a shrinking chain)
    # never leaves stale files behind and blows past the Pages file cap.
    shutil.rmtree(out / "block", ignore_errors=True)
    (out / "block").mkdir(parents=True, exist_ok=True)

    BLOCK_CHUNK = 1000  # blocks per file; keeps the deploy well under Cloudflare Pages' 20k-file cap
    summaries = []
    chunks = {}
    txids = {}
    for height, block in enumerate(blocks):
        txs = [explorer_tx(tx) for tx in block["transactions"]]
        detail = {
            "height": height,
            "hash": block["hash"],
            "prev": block["previous_hash"],
            "merkleRoot": block["merkle_root"],
            "version": block["version"],
            "time": block["time"],
            "bits": int(block["bits"], 16),
            "nonce": block["nonce"],
            "size": block["size"],
            "txs": txs,
        }
        cb = txs[0]["vout"][0] if txs and txs[0]["vout"] else {}
        summaries.append({
            "height": height,
            "hash": block["hash"],
            "time": block["time"],
            "nTx": len(txs),
            "size": block["size"],
            "cbValue": cb.get("value", 0),
            "cbAddr": cb.get("address", ""),
        })
        chunks.setdefault(height // BLOCK_CHUNK, {})[str(height)] = detail
        for tx in txs:
            txids.setdefault(tx["txid"][:2], {})[tx["txid"]] = height

    for ci, group in chunks.items():
        (out / "block" / ("%d.json" % ci)).write_text(
            json.dumps(group, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )

    # txid to height, in up to 256 files by the first byte. A swap is proven by
    # naming its transactions, and without this a reader has to know the block.
    shutil.rmtree(out / "tx", ignore_errors=True)
    (out / "tx").mkdir(parents=True, exist_ok=True)
    for prefix, group in txids.items():
        (out / "tx" / ("%s.json" % prefix)).write_text(
            json.dumps(group, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )

    summaries.sort(key=lambda x: -x["height"])
    estimate = network_estimate(blocks)
    network = "bitflash-testnet" if TESTNET else "bitflash"
    (out / "blocks.json").write_text(
        json.dumps({
            "network": network,
            "tipHeight": len(blocks) - 1,
            "count": len(blocks),
            "estimate": estimate,
            "blocks": summaries,
        }, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    # The front page of bitflash.network shows the height, the hashrate and
    # the newest few blocks. blocks.json has all of it but is megabytes; this
    # is the few hundred bytes it needs.
    (out / "tip.json").write_text(
        json.dumps({
            "network": network,
            "height": len(blocks) - 1,
            "time": blocks[-1]["time"] if blocks else None,
            "hashrate": (estimate or {}).get("hashrate"),
            "recent": [
                {k: s[k] for k in ("height", "hash", "time", "nTx", "size", "cbValue", "cbAddr")}
                for s in summaries[:6]
            ],
        }, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    # Cloudflare Pages reads this. Only the small files other sites read are
    # opened to other origins; the treasury ledgers are copied in by the
    # deploy, from the node that builds them, when they exist.
    (out / "_headers").write_text(
        "/tip.json\n  Access-Control-Allow-Origin: *\n"
        "/treasury.json\n  Access-Control-Allow-Origin: *\n"
        "/treasury-testnet.json\n  Access-Control-Allow-Origin: *\n",
        encoding="ascii",
    )
    # The asset URLs carry a hash of what they contain.
    #
    # Without it a returning visitor keeps whatever explorer.js their browser
    # cached, forever: the deploy that added the hashrate line went out with a
    # fresh index.html and a fresh blocks.json, and the page still ran the old
    # script, so the new element sat there empty. Measured on the live site, not
    # guessed -- showEstimate was undefined in a page whose HTML had the span.
    #
    # The hash only changes when the file does, so this costs nothing per deploy
    # and makes a stale asset impossible rather than unlikely.
    page, script = testnet_page() if TESTNET else (INDEX_HTML, EXPLORER_JS)
    js_tag = hashlib.sha256(script.encode("utf-8")).hexdigest()[:8]
    css_tag = hashlib.sha256(STYLE_CSS.encode("utf-8")).hexdigest()[:8]
    index = (page
             .replace('href="style.css"', 'href="style.css?v=%s"' % css_tag)
             .replace('src="explorer.js"', 'src="explorer.js?v=%s"' % js_tag))
    (out / "index.html").write_text(index, encoding="utf-8")
    (out / "style.css").write_text(STYLE_CSS, encoding="utf-8")
    (out / "explorer.js").write_text(script, encoding="utf-8")
    logo = Path(__file__).resolve().parents[1] / "docs" / "logo.png"
    if logo.exists():
        shutil.copyfile(logo, out / "logo.png")
    return len(blocks), len(blocks) - 1


def testnet_page():
    """The same page, saying which chain it shows: its coins are not worth anything."""
    page = re.sub(r'<p class="notice">.*?</p>\n', '', INDEX_HTML)
    for old, new in (
        ('<title>Bitflash Block Explorer</title>', '<title>Bitflash Testnet Explorer</title>'),
        ('Read-only Bitflash block explorer', 'Read-only explorer of the Bitflash test chain,'),
        ('<body>\n', '<body>\n<p class="notice">Public test chain: tBTF has no value and this chain can be reset. '
                     'Some for testing: <a href="https://faucet.bitflash.network/">the faucet</a>.</p>\n'),
        ('alt="">Bitflash</a>', 'alt="">Bitflash testnet</a>'),
        ('<a href="https://explorer.bitflash.network/" aria-current="page">', '<a href="https://explorer.bitflash.network/">'),
        ('<a href="https://testnet-explorer.bitflash.network/">', '<a href="https://testnet-explorer.bitflash.network/" aria-current="page">'),
        ('<h1>Block explorer</h1>', '<h1>Testnet explorer</h1>'),
        ('<span id="chainname">Main chain</span>', '<span id="chainname">Test chain</span>'),
        ('Read-only view of the main chain:', 'Read-only view of the test chain:'),
    ):
        assert old in page, old
        page = page.replace(old, new, 1)
    script = EXPLORER_JS.replace('+" BTF"; }', '+" tBTF"; }')
    assert script != EXPLORER_JS
    return page, script


def main(argv):
    args = parse_args(argv)
    raw_blocks = load_blocks(args)
    if not raw_blocks:
        raise SystemExit("no Bitflash blocks parsed")
    count, tip = build_explorer(raw_blocks, args.out_dir)
    print("explorer built: %d main-chain blocks, tip %d, into %s" % (count, tip, args.out_dir))
    return 0


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bitflash Block Explorer</title>
<meta name="description" content="Read-only Bitflash block explorer generated from local blk*.dat files.">
<link rel="icon" href="logo.png" type="image/png">
<link rel="stylesheet" href="style.css">
<script src="explorer.js" defer></script>
</head>
<body>
<p class="notice">First exchange listing: the NonKYC campaign needs 100 backers by 2027-02-04, and $5 counts as one. Pledges are donations, refunded if the listing does not happen. <a href="https://nonkyc.io/listing/campaign/BTF">Back the campaign &rarr;</a></p>
<header class="topbar">
  <a class="brand" href="https://bitflash.network/"><img src="logo.png" width="28" height="28" alt="">Bitflash</a>
  <nav aria-label="Bitflash sites">
    <a href="https://docs.bitflash.network/">Docs</a>
    <a href="https://releases.bitflash.network/">Downloads</a>
    <a href="https://explorer.bitflash.network/" aria-current="page">Explorer</a>
    <a href="https://testnet-explorer.bitflash.network/">Testnet</a>
    <a href="https://faucet.bitflash.network/">Faucet</a>
    <a href="https://github.com/bitflash-network/bitflash">Source</a>
  </nav>
  <span class="action"><a class="button" href="https://releases.bitflash.network/">Download</a></span>
</header>
<main>
  <p class="crumb">Explorer &middot; <span id="chainname">Main chain</span></p>
  <h1>Block explorer</h1>
  <p class="lede">Read-only view of the main chain: blocks, their transactions and the coinbase payout, rebuilt from a node's own block files at every block. There is no mempool and no per-address history here.</p>
  <div class="metrics">
    <div class="metric"><b id="m-height">&hellip;</b><span>Block height</span></div>
    <div class="metric"><b id="m-hash">&hellip;</b><span>Network hashrate, estimated</span></div>
    <div class="metric"><b id="m-interval">&hellip;</b><span>Average time between blocks</span></div>
    <div class="metric"><b id="m-count">&hellip;</b><span>Blocks in the chain</span></div>
  </div>
  <p class="note" id="netnote" hidden></p>
  <div id="listview">
    <input id="q" type="search" placeholder="Search by height, block hash or txid" aria-label="Search by height, block hash or txid" autocomplete="off" spellcheck="false">
    <div class="scroll"><table>
      <thead><tr><th>Height</th><th>Time (UTC)</th><th class="num">Txs</th><th class="num">Size</th><th class="num">Reward</th><th>To</th></tr></thead>
      <tbody id="rows"><tr><td colspan="6" class="mut">Reading the chain&hellip;</td></tr></tbody>
    </table></div>
    <p class="note" id="more"></p>
  </div>
  <div id="detail" hidden></div>
  <p><button class="back" id="home" hidden>&larr; Back to the newest blocks</button></p>
</main>
<footer>
  <div class="foot-cols">
    <div><h2>Software</h2><ul>
      <li><a href="https://releases.bitflash.network/">Downloads</a></li>
      <li><a href="https://docs.bitflash.network/">Documentation</a></li>
      <li><a href="https://github.com/bitflash-network/bitflash">Source code</a></li>
    </ul></div>
    <div><h2>Network</h2><ul>
      <li><a href="https://explorer.bitflash.network/">Block explorer</a></li>
      <li><a href="https://testnet-explorer.bitflash.network/">Testnet explorer</a></li>
      <li><a href="https://faucet.bitflash.network/">Testnet faucet</a></li>
      <li><a href="https://bitflash.network/treasury">Treasury</a></li>
    </ul></div>
    <div><h2>Community</h2><ul>
      <li><a href="https://bitflash.network/discord">Discord</a></li>
      <li><a href="https://x.com/BTFBitflash">X</a></li>
    </ul></div>
    <div><h2>This page</h2><ul>
      <li>No cookies and no trackers</li>
      <li>Static files built from blk*.dat</li>
    </ul></div>
  </div>
  <span class="wordmark" aria-hidden="true">Bitflash</span>
  <p class="legal">MIT licensed, built on Bitcoin 0.1.0 (Satoshi Nakamoto, 2009). The wallet has the same explorer built in, reading only your own node.</p>
</footer>
</body>
</html>
"""


STYLE_CSS = r"""/* The explorer in the bitflash.network look: one sans-serif face, monospace
   only for hashes and addresses, surfaces told apart by tone, lines only in
   the table. Self-contained: nothing is loaded from another host. */
:root{
  color-scheme: light dark;
  --bg:#ffffff; --bg-2:#eff3f0; --bg-3:#e2e9e4; --fg:#0b100d; --soft:#4b554f; --line:#d9e0db;
  --accent:#0e7339; --accent-2:#0a5c2d; --on-accent:#ffffff; --field:#1f9d57;
  --night:#0b100d; --night-ink:#e8ede9;
  --sans:"Inter","Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,BlinkMacSystemFont,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,"Cascadia Mono","SF Mono",Consolas,"DejaVu Sans Mono","Liberation Mono",monospace;
  --gutter:clamp(1rem,3vw,2.5rem);
}
@media (prefers-color-scheme: dark){:root{
  --bg:#0b100d; --bg-2:#131a16; --bg-3:#1b241f; --fg:#e8ede9; --soft:#a2ada6; --line:#26302a;
  --accent:#4fd88c; --accent-2:#7be6aa; --on-accent:#03200e; --night:#030504;
}}
*,*::before,*::after{box-sizing:border-box;}
html{background:var(--bg);color:var(--fg);font:17px/1.55 var(--sans);-webkit-text-size-adjust:100%;-webkit-font-smoothing:antialiased;}
body{margin:0;background:var(--bg);}
:focus-visible{outline:3px solid var(--field);outline-offset:3px;}
a{color:var(--accent);text-underline-offset:3px;}
a:hover{color:var(--accent-2);}

.notice{margin:0;padding:.7rem var(--gutter);background:var(--night);color:var(--night-ink);font-size:.88rem;line-height:1.5;}
.notice a,.notice a:visited{color:var(--night-ink);font-weight:650;white-space:nowrap;}
.notice a:hover{color:var(--field);}

.topbar{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:.6rem 2.2rem;min-height:4rem;padding:.6rem var(--gutter);background:var(--bg);}
.brand{display:flex;align-items:center;gap:.6rem;text-decoration:none;color:var(--fg);font-weight:750;font-size:1.15rem;letter-spacing:-.02em;white-space:nowrap;}
.brand:visited,.brand:hover{color:var(--fg);}
.brand img{width:28px;height:28px;display:block;}
.topbar nav{display:flex;flex-wrap:wrap;gap:.2rem 1.6rem;font-size:1rem;}
.topbar nav a,.topbar nav a:visited{text-decoration:none;color:var(--soft);}
.topbar nav a:hover{color:var(--fg);}
.topbar nav a[aria-current="page"]{color:var(--fg);font-weight:650;}
.topbar .action{margin-left:auto;}
a.button,a.button:visited{display:inline-flex;align-items:center;min-height:40px;padding:0 1rem;font:650 .93rem/1 var(--sans);text-decoration:none;background:var(--accent);color:var(--on-accent);transition:background-color .15s;}
a.button:hover{background:var(--accent-2);color:var(--on-accent);}
@media (max-width:720px){.topbar{flex-wrap:wrap;gap:.4rem 1.2rem;}.topbar nav{order:3;width:100%;gap:.2rem 1.1rem;font-size:.88rem;}}

main{padding:2.4rem var(--gutter) 6rem;min-width:0;max-width:110rem;}
.crumb{font-size:.88rem;color:var(--soft);margin:0 0 1.2rem;}
h1{font-size:clamp(2.1rem,4vw,3.4rem);font-weight:750;letter-spacing:-.03em;line-height:1.05;margin:0 0 1rem;}
h2{font-size:clamp(1.5rem,2.2vw,2rem);font-weight:700;letter-spacing:-.02em;line-height:1.15;margin:0 0 1rem;}
.lede{font-size:1.3rem;line-height:1.45;max-width:52ch;margin:0 0 2rem;}
.note{color:var(--soft);font-size:.88rem;max-width:70ch;margin:.4rem 0 1.4rem;}
.mut{color:var(--soft);}

.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(12rem,1fr));gap:clamp(1.5rem,3vw,3rem);margin:clamp(2rem,4vw,3rem) 0 1rem;}
.metric{min-width:0;}
.metric b{display:block;font-size:clamp(2rem,3.6vw,3.4rem);font-weight:750;letter-spacing:-.03em;line-height:1;font-variant-numeric:tabular-nums;overflow-wrap:anywhere;}
.metric span{display:block;margin-top:.6rem;font-size:.88rem;color:var(--soft);}

input{display:block;width:min(100%,48rem);height:3.2rem;margin:2rem 0 .6rem;padding:0 .9rem;border:0;border-radius:0;background:var(--bg-2);color:var(--fg);font:500 1.15rem/1 var(--sans);-webkit-appearance:none;appearance:none;}
input::placeholder{color:var(--soft);opacity:1;}

.scroll{overflow-x:auto;}
table{width:100%;border-collapse:collapse;margin-top:1rem;font-size:.93rem;}
th,td{text-align:left;padding:.7rem 1.4rem .7rem 0;border-bottom:1px solid var(--line);font-variant-numeric:tabular-nums;white-space:nowrap;}
th{font-weight:650;color:var(--soft);}
th.num,td.num{text-align:right;}
td:first-child{font-weight:650;color:var(--accent);}
tr.blk{cursor:pointer;transition:background-color .12s;}
tr.blk:hover{background:var(--bg-2);}
code{font-family:var(--mono);font-size:.84rem;word-break:break-all;color:inherit;}
td code{color:var(--soft);}

#detail h2{margin-top:1rem;}
#detail,.tx{scroll-margin-top:5rem;}
.card{background:var(--bg-2);padding:clamp(1.1rem,2.5vw,1.8rem);margin:1rem 0 2.4rem;max-width:72rem;}
.kv{display:grid;grid-template-columns:11rem minmax(0,1fr);gap:.5rem 1.2rem;font-size:.93rem;}
.kv > div:nth-child(odd){color:var(--soft);}
.tx{padding:1.2rem 0;border-top:1px solid var(--line);max-width:72rem;}
.tx.hit{background:var(--bg-2);padding-left:1rem;padding-right:1rem;}
.tx > div:first-child{display:flex;flex-wrap:wrap;gap:.4rem .8rem;align-items:baseline;margin-bottom:.8rem;}
.io{display:grid;grid-template-columns:1fr 1fr;gap:1.4rem;font-size:.93rem;}
.io > div > div{margin:.3rem 0;}
.io .mut{font-weight:650;color:var(--soft);}
.pill{display:inline-block;font-size:.8rem;padding:.1rem .55rem;background:var(--bg-3);color:var(--fg);}
button.link{background:none;border:0;color:var(--accent);cursor:pointer;font:inherit;padding:0;text-decoration:underline;text-underline-offset:3px;}
button.back{min-height:44px;padding:0 1.1rem;border:0;background:var(--bg-2);color:var(--fg);font:600 1rem/1 var(--sans);cursor:pointer;}
button.back:hover{background:var(--bg-3);}
@media (max-width:640px){.metrics{grid-template-columns:1fr 1fr;}.lede{font-size:1.1rem;}.io{grid-template-columns:1fr;}.kv{grid-template-columns:7rem minmax(0,1fr);}th:nth-child(4),td:nth-child(4){display:none;}}

footer{background:var(--night);color:var(--night-ink);padding:clamp(2.5rem,5vw,4rem) var(--gutter) 1.4rem;font-size:1rem;}
footer a,footer a:visited{color:var(--night-ink);text-decoration:none;}
footer a:hover{color:var(--field);text-decoration:underline;}
.foot-cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));gap:2rem;}
.foot-cols h2{font-size:1rem;font-weight:650;letter-spacing:0;margin:0 0 .8rem;color:var(--night-ink);}
.foot-cols ul{list-style:none;margin:0;padding:0;}
.foot-cols li{margin:0 0 .45rem;opacity:.72;}
.wordmark{display:block;margin:clamp(3rem,8vw,7rem) 0 0 -.04em;padding-bottom:.08em;font-size:clamp(4.4rem,27vw,30rem);font-weight:800;letter-spacing:-.055em;line-height:.8;white-space:nowrap;overflow:hidden;color:var(--night-ink);}
.legal{margin:1.6rem 0 0;font-size:.88rem;opacity:.72;}
@media (prefers-reduced-motion: reduce){*{transition:none !important;}}
"""


EXPLORER_JS = r"""
var SUM = [], SHOWN = 200;
function btf(sat){ return (sat/1e8).toFixed(8).replace(/0+$/,'').replace(/\.$/,'')+" BTF"; }
function ts(t){ return new Date(t*1000).toISOString().replace('T',' ').replace('.000Z',' UTC'); }
function short(h){ return h ? h.slice(0,10)+"..."+h.slice(-6) : "-"; }
function E(tag, cls, text){
  var e = document.createElement(tag);
  if(cls) e.className = cls;
  if(text !== undefined) e.textContent = text;
  return e;
}
function code(text){ return E('code', '', text); }
function clear(e){ while(e.firstChild) e.removeChild(e.firstChild); }
function append(parent){
  for(var i=1;i<arguments.length;i++) parent.appendChild(arguments[i]);
  return parent;
}
function row(cells, cls){
  var tr = E('tr', cls || '');
  cells.forEach(function(c){ append(tr, E('td', '', c)); });
  return tr;
}
function renderList(filter){
  var q=(filter||"").trim().toLowerCase(), rows=document.getElementById('rows');
  clear(rows);
  var list = q ? SUM.filter(function(b){ return String(b.height)===q || b.hash.indexOf(q)===0; }) : SUM.slice(0,SHOWN);
  if(!list.length && /^[0-9a-f]{64}$/.test(q)){ openTx(q); return; }
  if(!list.length){
    var empty = E('tr');
    var td = E('td', 'mut', 'No block matches that.');
    td.colSpan = 6;
    append(empty, td); append(rows, empty);
  }
  list.forEach(function(b){
    var tr = row([String(b.height), ts(b.time), String(b.nTx), b.size+' B', btf(b.cbValue), ''], 'blk');
    tr.children[2].className = tr.children[3].className = tr.children[4].className = 'num';
    tr.dataset.h = b.height;
    clear(tr.children[5]);
    append(tr.children[5], code(b.cbAddr || '-'));
    tr.onclick = function(){ openBlock(tr.dataset.h); };
    append(rows, tr);
  });
  document.getElementById('more').textContent = (!q && SUM.length>SHOWN) ? ("Showing the newest "+SHOWN+" of "+group(SUM.length)+" blocks. Search to find any other.") : "";
}
function kv(parent, key, value, isCode){
  append(parent, E('div', '', key));
  append(parent, isCode ? append(E('div'), code(value)) : E('div', '', value));
}
function ioSide(title, items, render){
  var side = E('div');
  append(side, E('div', 'mut', title));
  items.forEach(function(item){ append(side, render(item)); });
  return side;
}
function openTx(id){
  fetch('tx/'+id.slice(0,2)+'.json').then(function(r){ return r.ok ? r.json() : {}; }).then(function(heights){
    if(heights[id] !== undefined){ openBlock(heights[id], id); return; }
    var detail = document.getElementById('detail');
    clear(detail);
    append(detail, E('h2', '', 'Transaction not found'), append(E('p'), code(id)));
    document.getElementById('listview').hidden = true;
    detail.hidden = false;
    document.getElementById('home').hidden = false;
  });
}
function openBlock(h, txid){
  h = parseInt(h, 10);
  if(!(h >= 0)) return;
  var here = txid ? '#tx/'+txid : '#block/'+h;
  if(location.hash !== here) history.replaceState(null, '', here);
  fetch('block/'+Math.floor(h/1000)+'.json').then(function(r){return r.json();}).then(function(chunk){
    var b=chunk[h];
    if(!b){var dd=document.getElementById('detail');clear(dd);append(dd,E('h2','','Block '+h+' not found'));return;}
    var detail = document.getElementById('detail');
    clear(detail);
    append(detail, E('h2', '', 'Block '+b.height));
    var card = E('div', 'card'), grid = E('div', 'kv');
    kv(grid, 'Height', String(b.height));
    kv(grid, 'Hash', b.hash, true);
    var prev = E('div');
    if(b.height > 0){
      var btn = E('button', 'link');
      append(btn, code(short(b.prev)));
      btn.onclick = function(){ openBlock(b.height - 1); };
      append(prev, btn);
    } else {
      append(prev, code(short(b.prev)));
    }
    append(grid, E('div', '', 'Previous'), prev);
    kv(grid, 'Merkle root', b.merkleRoot, true);
    kv(grid, 'Time (UTC)', ts(b.time));
    kv(grid, 'Bits / Nonce', b.bits.toString(16)+' / '+b.nonce);
    kv(grid, 'Size / Txs', b.size+' B / '+b.txs.length);
    append(card, grid); append(detail, card);
    var hit = null;
    b.txs.forEach(function(t, i){
      var tx = E('div', 'tx');
      var head = E('div');
      append(head, code(t.txid));
      if(i === 0) append(head, E('span', 'pill', 'coinbase'));
      var io = E('div', 'io');
      append(io, ioSide('Inputs', t.vin, function(v){
        var d = E('div');
        if(v.coinbase){ append(d, E('span', 'pill', 'coinbase')); return d; }
        var spent = E('button', 'link');
        append(spent, code(short(v.prev)+':'+v.vout));
        spent.onclick = function(){ openTx(v.prev); };
        return append(d, spent);
      }));
      append(io, ioSide('Outputs', t.vout, function(o){
        var d = E('div');
        var to = o.address ? o.address : (o.pubkey ? 'pubkey '+o.pubkey.slice(0,16)+'...' : o.type);
        append(d, document.createTextNode(btf(o.value)+' to '), code(to));
        return d;
      }));
      append(tx, head, io); append(detail, tx);
      if(t.txid === txid){ tx.className = 'tx hit'; hit = tx; }
    });
    document.getElementById('listview').hidden = true;
    detail.hidden = false;
    document.getElementById('home').hidden = false;
    if(hit) hit.scrollIntoView(); else detail.scrollIntoView();
  });
}
document.getElementById('home').onclick=function(){
  document.getElementById('detail').hidden = true;
  document.getElementById('listview').hidden = false;
  this.hidden = true;
  history.replaceState(null, '', location.pathname);
};
function openFromHash(){
  var m = /^#block\/(\d+)$/.exec(location.hash);
  if(m) openBlock(m[1]);
  m = /^#tx\/([0-9a-f]{64})$/.exec(location.hash);
  if(m) openTx(m[1]);
}
window.addEventListener('hashchange', openFromHash);
document.getElementById('q').oninput=function(){ renderList(this.value); };
function group(n){ return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ','); }
function put(id, text){ var e = document.getElementById(id); if(e) e.textContent = text; }
function fmtHashrate(h){
  var u=['H/s','kH/s','MH/s','GH/s','TH/s','PH/s'], i=0;
  while(h>=1000 && i<u.length-1){ h/=1000; i++; }
  return (h>=100?h.toFixed(0):h.toFixed(2))+' '+u[i];
}
function showEstimate(e){
  if(!e || !e.hashrate) return;
  var mins = e.intervalSec/60;
  put('m-hash', fmtHashrate(e.hashrate));
  put('m-interval', mins.toFixed(1) + ' min');
  var note = document.getElementById('netnote');
  note.textContent =
    'Network hashrate is estimated, not measured: expected hashes per block is 2^256/(target+1), ' +
    'divided by how long blocks actually took over the last ' + e.window + ' blocks. Target ' + e.bits +
    ', aiming at a block every ' + (e.targetSpacing/60) + ' min. Finding a block is a Poisson process, ' +
    'so a quiet stretch and a lucky one both move this number without anyone\'s hardware changing.';
  note.hidden = false;
}
fetch('blocks.json').then(function(r){return r.json();}).then(function(d){
  SUM=d.blocks; put('m-height', group(d.tipHeight)); put('m-count', group(d.count));
  showEstimate(d.estimate);
  renderList('');
  openFromHash();
});
"""


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
