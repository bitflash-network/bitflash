// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Atomic swaps arranged in the chat: what an offer and a step look like.
//
// AN OFFER is a post in a public community (MSG_SWAP_OFFER): "I give 100 BTF,
// I want 0.001 BTC". Signed by whoever posted it, like any post, so a "take"
// goes to the person who really made it.
//
// THE STEPS go in the conversation between the two (MSG_SWAP), each the text
// of a signed frame:
//
//   take      taker -> maker   these terms, and where I want your coin
//   lock1     maker -> taker   I locked my coin: contract, where it is, and
//                              where I want yours
//   lock2     taker -> maker   I locked mine under your secret hash
//   redeemed  maker -> taker   I took yours (the secret is on that chain now)
//   cancel    either           before anything of the sender's is locked
//
// None of these moves a coin by itself. Each side's app checks every claim on
// its own nodes -- the Bitflash chain through the wallet, Bitcoin through the
// person's Bitcoin Core -- before it locks anything, and the secret is read
// off the chain, not taken from a message. A lying step costs the liar
// nothing but the swap; it cannot take anybody's coins.
//
// Pure: no wallet, no network. The swap itself is btfchatswap.h.

#ifndef BITFLASH_CHATSWAP_H
#define BITFLASH_CHATSWAP_H

#include <string>
#include <stdint.h>
#include "coinunit.h"

namespace btfchat
{

static const size_t MAX_SWAP_NOTE = 200;

// What an offer and a take carry as "v". 2: a Bitflash contract is locked by
// time (median time past), never by height (swap.h, THE TIMING). An offer or
// a take without it was made by a version that locks Bitflash by height: it
// is refused before anybody locks anything, rather than half understood.
static const int SWAP_PROTOCOL_VERSION = 2;

// 21 million coins, in satoshis, on either side.
static const int64_t MAX_SWAP_AMOUNT = (int64_t)21000000 * 100000000;

struct SwapOffer
{
    std::string give;      // "BTF", "BTC" or "LTC": what the person posting it gives
    int64_t     giveAmount;
    std::string want;      // the other one
    int64_t     wantAmount;
    std::string note;

    SwapOffer() : giveAmount(0), wantAmount(0) {}
};

// Neither parser throws, whatever the text: a field of the wrong type is a
// refusal with errOut, like any other malformed offer or step.
bool ParseSwapOffer(const std::string& text, SwapOffer& out, std::string& errOut);
std::string FormatSwapOffer(const SwapOffer& o);
// The least an offer may give or ask on that coin, in its base units: a
// contract under it costs more to spend than it holds, so the side that
// locked against it could be taken and receive nothing it can spend.
int64_t SwapMinAmount(const std::string& coin);
// "100 BTF for 0.001 BTC"
std::string DescribeSwapOffer(const SwapOffer& o);

struct SwapStep
{
    std::string swap;      // 32 hex: names the swap in every step
    std::string step;      // take, lock1, lock2, redeemed, cancel

    // take: the offer (its frame id) and its terms, as the maker posted them
    std::string offer;
    SwapOffer   terms;

    // take: where the taker wants the maker's coin. lock1: where the maker
    // wants the taker's.
    std::string to;

    // lock1, lock2: the contract and where it was funded. vout is -1 for a
    // Bitflash contract (found by its txid), the output index on Bitcoin.
    std::string chain;     // "BTF", "BTC" or "LTC"
    std::string contract;  // hex
    std::string txid;
    int         vout;

    std::string why;       // cancel

    SwapStep() : vout(-1) {}
};

bool ParseSwapStep(const std::string& text, SwapStep& out, std::string& errOut);
std::string FormatSwapStep(const SwapStep& s);

bool SwapCoinOk(const std::string& coin);
// The shape of an address on that coin: a B address for BTF, a legacy key
// address for BTC (1..., m..., n...). The wallet checks the checksum.
bool SwapAddressShapeOk(const std::string& coin, const std::string& addr);

std::string FormatSwapAmount(const std::string& coin, int64_t n);

} // namespace btfchat

#endif
