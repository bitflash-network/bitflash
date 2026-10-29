// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// The P2Pool payout split: every node must reach the same outputs, to the
// satoshi, from the same window, in whatever order it holds the shares.

#include "p2pool.h"

#include <stdio.h>
#include <algorithm>

using namespace p2pool;

static int nFail = 0;

static void Check(bool f, const char* what)
{
    printf("  %s %s\n", f ? "ok  " : "FAIL", what);
    if (!f)
        nFail++;
}

static std::vector<unsigned char> Script(unsigned char tag)
{
    // A P2PKH-shaped script whose key hash is 20 copies of tag.
    std::vector<unsigned char> s;
    s.push_back(0x76); s.push_back(0xa9); s.push_back(20);
    for (int i = 0; i < 20; i++) s.push_back(tag);
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

static WindowShare Share(unsigned char tag, uint64_t work)
{
    WindowShare w;
    w.payoutScript = Script(tag);
    w.work = work;
    return w;
}

static int64_t Sum(const std::vector<Payout>& v)
{
    int64_t n = 0;
    for (size_t i = 0; i < v.size(); i++) n += v[i].value;
    return n;
}

int main()
{
    printf("p2pool payout tests\n");
    const int64_t COIN = 100000000;
    std::vector<Payout> out;
    std::string err;

    // One miner takes everything.
    std::vector<WindowShare> one(5, Share(1, 1000));
    Check(ComputePayouts(one, 50 * COIN, out, err) && out.size() == 1 && out[0].value == 50 * COIN,
          "one miner, five shares: one output with the whole block");

    // 1 : 3 by work, not by number of shares.
    std::vector<WindowShare> w;
    w.push_back(Share(2, 1000));
    w.push_back(Share(3, 1500));
    w.push_back(Share(3, 1500));
    Check(ComputePayouts(w, 40 * COIN, out, err) && out.size() == 2 &&
          out[0].value == 10 * COIN && out[1].value == 30 * COIN,
          "split by work: 1000 against 3000 is 10 and 30 of 40");

    // Rounding: 1 satoshi over three equal miners, then 100 satoshis.
    std::vector<WindowShare> three;
    three.push_back(Share(4, 7)); three.push_back(Share(5, 7)); three.push_back(Share(6, 7));
    Check(ComputePayouts(three, 100, out, err) && Sum(out) == 100 &&
          out[0].value == 34 && out[1].value == 33 && out[2].value == 33,
          "100 satoshis over three equal miners: 34, 33, 33 (the remainder to the first in order)");

    // The remainder goes to the most work, not to the first in order.
    std::vector<WindowShare> uneven;
    uneven.push_back(Share(7, 1)); uneven.push_back(Share(8, 2));
    Check(ComputePayouts(uneven, 10, out, err) && Sum(out) == 10 && out[0].value == 3 && out[1].value == 7,
          "the remainder goes to the miner with the most work");

    // Same window in any order: same outputs, byte for byte.
    std::vector<WindowShare> big;
    for (int i = 0; i < 2160; i++)
        big.push_back(Share((unsigned char)(i % 37 + 1), 1000003ULL * (uint64_t)(i % 11 + 1)));
    std::vector<Payout> a, b;
    bool fa = ComputePayouts(big, 50 * COIN + 12345, a, err);
    std::reverse(big.begin(), big.end());
    std::swap(big[0], big[1000]);
    bool fb = ComputePayouts(big, 50 * COIN + 12345, b, err);
    bool same = fa && fb && a.size() == b.size();
    for (size_t i = 0; same && i < a.size(); i++)
        same = a[i].script == b[i].script && a[i].value == b[i].value;
    Check(same && a.size() == 37, "2160 shares in another order: the same 37 outputs, to the satoshi");
    Check(fa && Sum(a) == 50 * COIN + 12345, "and they add up to the block value exactly");
    bool sorted = true;
    for (size_t i = 1; i < a.size(); i++)
        sorted = sorted && a[i - 1].script < a[i].script;
    Check(sorted, "outputs come sorted by script");

    // Huge work values do not overflow.
    std::vector<WindowShare> huge(2160, Share(9, 0xFFFFFFFFFFFFFFFFULL));
    huge.push_back(Share(10, 0xFFFFFFFFFFFFFFFFULL));
    Check(ComputePayouts(huge, 50 * COIN, out, err) && Sum(out) == 50 * COIN &&
          out[1].value == 50 * COIN / 2161 &&
          out[0].value == 50 * COIN - out[1].value,
          "work near 2^64 per share does not overflow");

    // Refusals.
    Check(!ComputePayouts(std::vector<WindowShare>(), 1, out, err), "an empty window is refused");
    std::vector<WindowShare> zero(1, Share(1, 0));
    Check(!ComputePayouts(zero, 1, out, err), "a share with no work is refused");
    WindowShare noscript; noscript.work = 1;
    Check(!ComputePayouts(std::vector<WindowShare>(1, noscript), 1, out, err), "a share with no script is refused");
    Check(!ComputePayouts(one, -1, out, err), "a negative value is refused");
    Check(ComputePayouts(one, 0, out, err) && out.size() == 1 && out[0].value == 0,
          "a block worth nothing pays nothing, without failing");

    printf("%s (%d failure%s)\n", nFail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED",
           nFail, nFail == 1 ? "" : "s");
    return nFail ? 1 : 0;
}
