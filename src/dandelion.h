// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Dandelion++ for transactions (the design of BIP156, as Monero runs it).
// Every Bitflash connection carries a .btf identity, so a peer that receives a
// transaction from us first knows who sent it, Tor or not. Dandelion hides the
// origin: a new transaction first walks a "stem", one peer at a time, and each
// hop has a 1 in 10 chance to "fluff" it -- announce it to everyone, as before.
// A peer handed a stem transaction cannot tell whether its neighbour wrote it
// or only passed it on.
//
// Routes are fixed for an epoch (10 minutes): everything that arrives from one
// neighbour leaves through the same relay, so a spy cannot learn the source by
// comparing routes. A stem that dies -- a relay that drops it -- is caught by
// the embargo: whoever forwarded it fluffs it itself after 30 to 60 seconds if
// nobody else has.
//
// Peers say they take stem transactions with "stemok" after the version
// handshake. Nodes from before Dandelion never say it, and are never relays.
#ifndef BITFLASH_DANDELION_H
#define BITFLASH_DANDELION_H

#include <stddef.h>
#include <stdint.h>
#include <map>
#include <vector>

namespace dandelion
{

static const int64_t EPOCH_SECONDS = 600;
static const int FLUFF_PERCENT = 10;
static const int64_t EMBARGO_MIN_SECONDS = 30;
static const int64_t EMBARGO_SPREAD_SECONDS = 30;
static const unsigned int RELAYS_PER_EPOCH = 2;

// Our own transactions, with Tor: each over a connection and circuit of its
// own (dandelion.cpp), a few random seconds after the wallet made it.
static const int64_t ONESHOT_DELAY_MIN_SECONDS = 2;
static const int64_t ONESHOT_DELAY_SPREAD_SECONDS = 10;
static const int ONESHOT_CONNECT_SECONDS = 120;
static const int64_t ONESHOT_HANDSHAKE_SECONDS = 60;
static const int64_t ONESHOT_STEMOK_WAIT_SECONDS = 5;
static const size_t ONESHOT_MAX_READ = 4 * 1024 * 1024;
static const int ONESHOT_TRIES = 3;

// The routing of one node, with peers as opaque ids (0 = this node itself).
// Pure: the network glue feeds it peers and coins, tests feed it numbers.
class Router
{
public:
    Router() : nEpochStart(0) {}

    // Start an epoch: up to RELAYS_PER_EPOCH relays picked from the
    // candidates (outbound peers that said stemok) with the given random
    // values, and every earlier route forgotten.
    void NewEpoch(int64_t nNow, const std::vector<uint64_t>& vCandidates, const std::vector<uint64_t>& vRandom);
    bool EpochOver(int64_t nNow) const { return nEpochStart == 0 || nNow - nEpochStart >= EPOCH_SECONDS; }

    // The relay for stem transactions arriving from 'from' (0: our own):
    // the same one for the whole epoch, picked with r the first time. 0 when
    // there is none, or when the only relay is the sender itself.
    uint64_t RelayFor(uint64_t from, uint64_t r);

    // Fluff here? r is uniform in [0, 100).
    static bool Fluff(unsigned int r) { return r < (unsigned int)FLUFF_PERCENT; }

    const std::vector<uint64_t>& Relays() const { return vRelays; }

private:
    int64_t nEpochStart;
    std::vector<uint64_t> vRelays;
    std::map<uint64_t, uint64_t> mapRoute;
};

} // namespace dandelion

#ifndef BITFLASH_DANDELION_PURE
class CNode;
class CTransaction;
class CDataStream;

class CAddress;

// Our own new transaction. With Tor: a few seconds later, over a connection
// and circuit of its own to a random peer. Without Tor, or when no peer can
// be reached that way: into the stem, or fluffed when no relay takes it.
// vParents: unconfirmed transactions it spends that may not have spread yet;
// they travel with it, ahead of it.
void DandelionRelayOwn(const CTransaction& tx, const std::vector<CTransaction>& vParents);
// One such connection: version, then each of vtx as "stemtx" (or "tx" to a
// peer that never says stemok), then close. strHow says what happened.
// Exposed for the tests.
bool DandelionSendOneShot(const std::vector<CTransaction>& vtx, const std::string& strHost, unsigned short nPort,
                          const CAddress& addrYou, const std::string& strIsolation, std::string& strHow);
// "stemok" and "stemtx"; false when strCommand is neither. Under cs_main.
bool DandelionProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv);
// After the version handshake.
void DandelionOnVersion(CNode* pfrom);
// A transaction seen fluffed (an inv or tx from a peer): its embargo is over.
void DandelionSeenFluffed(const uint256& hash);
// Fluff what is past its embargo; renew the epoch. Called often, cheap.
void DandelionTick();
#endif

#endif
