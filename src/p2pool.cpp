// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "p2pool.h"

#include <map>

namespace p2pool
{

bool ComputePayouts(const std::vector<WindowShare>& window, int64_t nValue,
                    std::vector<Payout>& out, std::string& errOut)
{
    out.clear();
    errOut.clear();
    if (window.empty())
    {
        errOut = "empty payout window";
        return false;
    }
    if (nValue < 0)
    {
        errOut = "negative block value";
        return false;
    }

    // std::map orders the scripts byte by byte: the same on every node,
    // whatever order the window arrived in.
    std::map<std::vector<unsigned char>, unsigned __int128> work;
    unsigned __int128 total = 0;
    for (size_t i = 0; i < window.size(); i++)
    {
        if (window[i].payoutScript.empty() || window[i].work == 0)
        {
            errOut = "a share with no payout script or no work";
            return false;
        }
        work[window[i].payoutScript] += window[i].work;
        total += window[i].work;
    }

    // nValue * work fits in 128 bits: nValue < 2^63 and the total work of a
    // window of 2160 64-bit values is < 2^75.
    int64_t paid = 0;
    std::map<std::vector<unsigned char>, unsigned __int128>::const_iterator best = work.end();
    for (std::map<std::vector<unsigned char>, unsigned __int128>::const_iterator it = work.begin();
         it != work.end(); ++it)
    {
        Payout p;
        p.script = it->first;
        p.value = (int64_t)(((unsigned __int128)nValue * it->second) / total);
        paid += p.value;
        out.push_back(p);
        if (best == work.end() || it->second > best->second)
            best = it;
    }

    // The rounding remainder, never more than one satoshi per output.
    for (size_t i = 0; i < out.size(); i++)
        if (out[i].script == best->first)
            out[i].value += nValue - paid;
    return true;
}

} // namespace p2pool
