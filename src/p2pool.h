// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// P2Pool inside the node (docs/p2pool.md). Every mining node keeps a share
// chain, and every block template pays, in its own coinbase, the miners of the
// last shares in proportion to their work. All nodes must compute that payout
// list identically, to the satoshi, or they would reject each other's shares;
// so it is a pure function of the window, with no floating point and a fixed
// order.
#ifndef BITFLASH_P2POOL_H
#define BITFLASH_P2POOL_H

#include <stdint.h>
#include <string>
#include <vector>

namespace p2pool
{

// Shares in the payout window (docs/p2pool.md: PPLNS, 2160 shares).
static const unsigned int WINDOW_SHARES = 2160;

// One share of the window: who it pays and how much work it counts for. An
// uncle's work arrives here already scaled (80% to it, 20% to the share that
// included it); this function only divides.
struct WindowShare
{
    std::vector<unsigned char> payoutScript;
    uint64_t work;
};

struct Payout
{
    std::vector<unsigned char> script;
    int64_t value;
};

// Splits nValue over the window in proportion to work: one output per
// distinct script, sorted by script bytes. Each gets floor(nValue * work /
// total); what rounding leaves goes to the script with the most work (the
// first in sort order on a tie). The outputs add up to nValue exactly.
// Refuses an empty window, a share with no work or no script, and nValue outside 0 to 2^51.
bool ComputePayouts(const std::vector<WindowShare>& window, int64_t nValue,
                    std::vector<Payout>& out, std::string& errOut);

} // namespace p2pool

#endif
