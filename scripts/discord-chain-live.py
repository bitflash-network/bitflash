#!/usr/bin/env python3
"""Post the chain's state to a Discord channel through a webhook.

    DISCORD_WEBHOOK=... python3 scripts/discord-chain-live.py daily
    DISCORD_WEBHOOK=... python3 scripts/discord-chain-live.py milestone
    python3 scripts/discord-chain-live.py daily --dry-run

daily      one summary: height, hashrate, the next halving, upcoming network
           dates and the latest release.
milestone  posts only when the height crossed a multiple of MILESTONE since
           the last run (the workflow runs it every 6 hours, about 180 blocks,
           so the window below is a little wider than that).

It reads only public data: the explorer's tip.json and GitHub's latest-release
API. Nothing here touches a node, and no server of the project runs it: the
GitHub Actions workflow .github/workflows/discord-chain-live.yml does.

The coinbase address is not shown as a miner count: the node rotates its
coinbase key every block, so distinct addresses do not mean distinct miners.
"""

import datetime as dt
import json
import os
import sys
import urllib.request

TIP_URL = "https://explorer.bitflash.network/tip.json"
RELEASE_URL = "https://api.github.com/repos/bitflash-network/bitflash/releases/latest"
HALVING_INTERVAL = 210_000
BLOCK_SECONDS = 120
MILESTONE = 5_000
MILESTONE_WINDOW = 240  # blocks: a 6-hour run interval is about 180

# Network dates worth counting down to. Past ones drop out on their own.
DATES = [
    (dt.datetime(2026, 11, 20, 12, tzinfo=dt.timezone.utc), "Rules v4 on testnet"),
    (dt.datetime(2026, 11, 21, 12, tzinfo=dt.timezone.utc),
     "Rules v3 on mainnet: every node should run 1.2.33 or newer"),
    (dt.datetime(2026, 12, 25, 12, tzinfo=dt.timezone.utc),
     "Rules v4 and atomic swaps on mainnet"),
]

USER_AGENT = "bitflash-discord-chain-live"


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def fmt_hashrate(hs):
    for unit, scale in (("MH/s", 1e6), ("kH/s", 1e3)):
        if hs >= scale:
            return f"{hs / scale:.1f} {unit}"
    return f"{hs:.0f} H/s"


def fmt_eta(seconds):
    days = seconds / 86400
    if days >= 2:
        return f"about {days:.0f} days"
    hours = seconds / 3600
    return f"about {hours:.0f} hours"


def countdown_lines(now):
    out = []
    for when, what in DATES:
        left = (when - now).total_seconds()
        if left <= 0:
            continue
        stamp = when.strftime("%Y-%m-%d %H:%M UTC")
        out.append(f"- **{what}**: {stamp}, in {fmt_eta(left)}")
    return out


def daily_message(tip, release, now):
    height = int(tip["height"])
    to_halving = HALVING_INTERVAL - height % HALVING_INTERVAL
    lines = [
        f"**Bitflash today** ({now.strftime('%Y-%m-%d')})",
        f"- Height: **{height:,}**",
        f"- Network hashrate: **{fmt_hashrate(float(tip['hashrate']))}**",
        f"- Next halving in {to_halving:,} blocks ({fmt_eta(to_halving * BLOCK_SECONDS)})",
    ]
    if release:
        lines.append(f"- Latest release: **{release['tag_name']}**, {release['html_url']}")
    dates = countdown_lines(now)
    if dates:
        lines.append("")
        lines.append("**Coming up**")
        lines.extend(dates)
    lines.append("")
    lines.append("Explorer: https://explorer.bitflash.network")
    return "\n".join(lines)


def milestone_message(tip):
    height = int(tip["height"])
    mark = height - height % MILESTONE
    if mark == 0 or height - mark > MILESTONE_WINDOW:
        return None
    return (f"**Block {mark:,} reached.** The chain is at {height:,} now, "
            f"with {fmt_hashrate(float(tip['hashrate']))} of network hashrate. "
            "https://explorer.bitflash.network")


def post(webhook, content):
    body = json.dumps({"content": content, "allowed_mentions": {"parse": []}}).encode()
    req = urllib.request.Request(webhook, data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()


def main(argv):
    if len(argv) < 2 or argv[1] not in ("daily", "milestone"):
        print(__doc__)
        return 2
    mode = argv[1]
    dry = "--dry-run" in argv
    tip = get_json(TIP_URL)
    now = dt.datetime.now(dt.timezone.utc)
    if mode == "daily":
        try:
            release = get_json(RELEASE_URL)
        except Exception as e:  # the summary is still useful without it
            print(f"latest release unavailable: {e}", file=sys.stderr)
            release = None
        content = daily_message(tip, release, now)
    else:
        content = milestone_message(tip)
        if content is None:
            print("no milestone in this window")
            return 0
    if dry:
        print(content)
        return 0
    webhook = os.environ.get("DISCORD_WEBHOOK", "").strip()
    if not webhook:
        print("DISCORD_WEBHOOK is not set; nothing was posted", file=sys.stderr)
        return 0
    post(webhook, content)
    print(f"posted {mode} ({len(content)} chars)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
