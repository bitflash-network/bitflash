// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "btfchatnode.h"
#include "btfchatsock.h"
#include "btfchatbox.h"
#include "btfaddr.h"
#include "btfchatnet.h"
#include "btfchatwallet.h"
#include "community.h"
#include "chatdir.h"
#include "btfchatswap.h"
#ifdef snprintf
#undef snprintf
#endif
#include <nlohmann/json.hpp>
#include "tor.h"

#include <sodium.h>
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>

#include <algorithm>
#include <deque>
#include <set>

namespace btfchat
{

// ---- the seed --------------------------------------------------------------

bool ChatSeedFromWallet(std::vector<unsigned char>& out, std::string& errOut)
{
    out.clear();
    errOut.clear();

    if (!HaveHDSeed())
    {
        // Either a wallet from before recovery phrases existed, or an encrypted
        // one that is still locked -- the master key is not readable either way,
        // and guessing which would be worse than saying both.
        errOut = "this wallet has no recovery phrase installed, or is locked";
        return false;
    }

    // master || chain code. Both are exactly the two halves of the HMAC-SHA512
    // that BIP32 computes over the BIP39 seed, so this is as deterministic as the
    // seed itself and carries the same entropy.
    out.reserve(64);
    out.insert(out.end(), vchHDMaster.begin(), vchHDMaster.end());
    out.insert(out.end(), vchHDChainCode.begin(), vchHDChainCode.end());
    if (out.size() != 64)
    {
        sodium_memzero(&out[0], out.size());
        out.clear();
        errOut = "the wallet's HD seed is the wrong size";
        return false;
    }
    return true;
}

bool UnlockIdentity(const std::string& password, Identity& out, std::string& errOut)
{
    errOut.clear();
    std::vector<unsigned char> seed;
    if (!ChatSeedFromWallet(seed, errOut))
        return false;

    bool fOk = DeriveIdentityFromSeed(seed, password, out, errOut);
    sodium_memzero(&seed[0], seed.size());
    return fOk;
}

// ---- the session -----------------------------------------------------------

static CCriticalSection cs_chat;

static bool               g_fUnlocked = false;
static Identity           g_id;
static Roster             g_roster;
static ReplayGuard        g_replay;
static History            g_history;
// What could not be sent yet. Sealed with the rest of the store, never anywhere
// else: this is the whole of "offline delivery" in this build.
static Outbox             g_outbox;
// Set when something makes it worth trying the queue right away -- today, the
// peer writing to us, which proves they are online.
static volatile bool      g_fFlushOutbox = false;
static AutoLock           g_lock;
static secp256k1_context* g_secp = NULL;

// Our own mailbox keys, and how far back we have already asked each tag.
static Mailbox g_mailbox;
static std::map<std::string, int64_t> g_mapPolledUntil;   // tag -> last 'since'

static unsigned short g_chatPort = 0;
static bool           g_fServiceStarted = false;
static bool           g_fListening = false;
static std::string    g_status = "off";
static btf_socket_t   g_listener = INVALID_SOCKET;

// Defined with the connection pool below. Declared here because locking the
// session has to close the live channels, and locking is defined first.
static void CloseAllOutLinks();

// The public communities we joined (community.h): id -> key and name. In the
// sealed store with everything else -- which rooms a person reads is as
// private as who they talk to. Read and written holding cs_chat.
struct JoinedCommunity
{
    std::vector<unsigned char> key;
    std::string name;
};
static std::map<std::string, JoinedCommunity> g_communities;

static std::string CommunitiesToJson()
{
    nlohmann::json a = nlohmann::json::array();
    for (std::map<std::string, JoinedCommunity>::const_iterator it = g_communities.begin();
         it != g_communities.end(); ++it)
    {
        nlohmann::json e;
        e["k"] = HexStr(it->second.key.begin(), it->second.key.end(), false);
        e["n"] = it->second.name;
        a.push_back(e);
    }
    return a.dump();
}

static void CommunitiesFromJson(const std::string& s)
{
    g_communities.clear();
    if (s.empty())
        return;
    try
    {
        nlohmann::json a = nlohmann::json::parse(s);
        if (!a.is_array())
            return;
        for (size_t i = 0; i < a.size() && i < 256; i++)
        {
            std::string k = a[i].value("k", std::string());
            std::string n = a[i].value("n", std::string());
            if (k.size() != 64 || !IsHex(k) || !community::NameOk(n))
                continue;
            JoinedCommunity c;
            c.key = ParseHex(k);
            c.name = n;
            g_communities[community::IdHex(&c.key[0])] = c;
        }
    }
    catch (...) {}
}

std::string ChatStorePath() { return GetAppDir() + "/btfchat.dat"; }

static bool EnsureSecp()
{
    if (g_secp)
        return true;
    g_secp = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!g_secp)
        return false;
    unsigned char rnd[32];
    RAND_bytes(rnd, sizeof(rnd));
    if (!secp256k1_context_randomize(g_secp, rnd))
    {
        secp256k1_context_destroy(g_secp);
        g_secp = NULL;
        return false;
    }
    return true;
}

// The sealed store: roster and history in one file under the identity's store
// key. Read while holding cs_chat.
static bool LoadStore()
{
    FILE* f = fopen(ChatStorePath().c_str(), "rb");
    if (!f)
        return true;   // nothing saved yet is not a failure

    std::vector<unsigned char> blob;
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    {
        blob.insert(blob.end(), buf, buf + n);
        // A file bigger than this is not ours. Bounded because it is a file on
        // disk that something else could have grown.
        if (blob.size() > 32u * 1024u * 1024u)
        {
            fclose(f);
            printf("btfchat: the store file is implausibly large, ignoring it\n");
            return false;
        }
    }
    fclose(f);
    if (blob.empty())
        return true;

    std::string plain;
    if (!OpenStore(g_id, &blob[0], blob.size(), plain))
    {
        // The usual cause is a different session password: this file belongs to
        // another identity. Not an error, and emphatically not something to
        // overwrite without being told to.
        printf("btfchat: the store does not belong to this identity\n");
        return false;
    }

    // The halves are stored as one object so a single seal covers all of them.
    std::string err;
    size_t nSplit = plain.find('\n');
    if (nSplit == std::string::npos)
        return false;
    std::string strRoster = plain.substr(0, nSplit);
    std::string strRest = plain.substr(nSplit + 1);
    // The outbox is the third line and arrived later than the other two. A store
    // written before it existed has two lines and must still load: an upgrade
    // that cannot read yesterday's file is an upgrade that erases a history.
    std::string strHistory = strRest;
    std::string strOutbox;
    std::string strCommunities;
    size_t nSplit2 = strRest.find('\n');
    if (nSplit2 != std::string::npos)
    {
        strHistory = strRest.substr(0, nSplit2);
        strOutbox  = strRest.substr(nSplit2 + 1);
        // And the communities joined, fourth, for the same reason.
        size_t nSplit3 = strOutbox.find('\n');
        if (nSplit3 != std::string::npos)
        {
            strCommunities = strOutbox.substr(nSplit3 + 1);
            strOutbox = strOutbox.substr(0, nSplit3);
        }
    }
    // The swaps in progress, fifth: secrets and contracts that, lost, leave
    // coins locked until a refund nobody remembers to make.
    std::string strSwaps;
    size_t nSplit4 = strCommunities.find('\n');
    if (nSplit4 != std::string::npos)
    {
        strSwaps = strCommunities.substr(nSplit4 + 1);
        strCommunities = strCommunities.substr(0, nSplit4);
    }
    CommunitiesFromJson(strCommunities);
    SwapsFromJson(strSwaps);
    if (!g_roster.FromJson(strRoster, err))
        printf("btfchat: the roster in the store did not load: %s\n", err.c_str());
    if (!strHistory.empty() && !g_history.FromJson(strHistory, err))
        printf("btfchat: the history in the store did not load: %s\n", err.c_str());
    if (!strOutbox.empty() && !g_outbox.FromJson(strOutbox, err))
        printf("btfchat: the outbox in the store did not load: %s\n", err.c_str());
    return true;
}

static bool SaveStore()
{
    if (!g_fUnlocked)
        return false;
    // One line of roster, then the history: newline-separated because neither
    // half's JSON contains a raw newline, and it keeps the seal to one blob.
    std::string plain = g_roster.ToJson() + "\n" + g_history.ToJson()
                      + "\n" + g_outbox.ToJson() + "\n" + CommunitiesToJson()
                      + "\n" + SwapsToJson();
    std::vector<unsigned char> sealed;
    if (!SealStore(g_id, plain, sealed))
        return false;
    sodium_memzero(&plain[0], plain.size());

    std::string strTmp = ChatStorePath() + ".new";
    FILE* f = fopen(strTmp.c_str(), "wb");
    if (!f)
        return false;
    bool fOk = fwrite(&sealed[0], 1, sealed.size(), f) == sealed.size();
    fflush(f);
    fclose(f);
    if (!fOk)
    {
        unlink(strTmp.c_str());
        return false;
    }
    // Write beside and rename, so an interrupted save cannot leave a truncated
    // store where a good one was.
    unlink(ChatStorePath().c_str());
    return rename(strTmp.c_str(), ChatStorePath().c_str()) == 0;
}

bool ChatUnlock(const std::string& password, std::string& errOut)
{
    errOut.clear();
    if (!EnsureSecp())
    {
        errOut = "secp256k1 context failed";
        return false;
    }

    Identity id;
    if (!UnlockIdentity(password, id, errOut))
        return false;

    CRITICAL_BLOCK(cs_chat)
    {
        if (g_fUnlocked)
            IdentityClear(g_id);
        g_id = id;
        g_fUnlocked = true;
        g_roster = Roster();
        g_history = History();
        g_outbox.Wipe();
        g_communities.clear();
        SwapsClear();
        g_lock.Unlock(GetTime());
        LoadStore();
        // Epoch keys are random and kept, never derived, so they have to exist
        // before anyone can leave us anything -- and they are destroyed with the
        // session, which is what makes an old envelope unreadable by everyone.
        std::string e;
        if (!g_mailbox.Rotate(GetTime(), e))
            printf("btfchat: could not make epoch keys: %s\n", e.c_str());
    }
    IdentityClear(id);
    printf("btfchat: unlocked as %s\n", ChatAddress().c_str());
    return true;
}

void ChatLock()
{
    bool fCloseLinks = false;
    CRITICAL_BLOCK(cs_chat)
    {
        if (g_fUnlocked)
            SaveStore();
        IdentityClear(g_id);
        g_roster = Roster();
        g_history = History();
        // The queue is sealed on disk and reloaded at the next unlock, so
        // dropping it from memory loses nothing and keeps a locked session with
        // no plaintext in it.
        g_outbox.Wipe();
        g_communities.clear();
        SwapsClear();
        // The epoch secrets go with the session. An envelope sealed to them is
        // unreadable afterwards by anybody, us included: that is the forward
        // secrecy, and keeping them would quietly throw it away.
        g_mailbox.Wipe();
        g_mapPolledUntil.clear();
        g_fUnlocked = false;
        g_lock.Lock();
        fCloseLinks = true;
    }
    if (fCloseLinks)
        CloseAllOutLinks();
}

bool ChatUnlocked()
{
    CRITICAL_BLOCK(cs_chat)
        return g_fUnlocked && !g_lock.IsLocked(GetTime());
    return false;
}

std::string ChatAddress()
{
    CRITICAL_BLOCK(cs_chat)
        return g_fUnlocked ? g_id.address : std::string();
    return std::string();
}

void ChatTouch()
{
    CRITICAL_BLOCK(cs_chat)
        g_lock.Touch(GetTime());
}

bool ChatCheckInactivity()
{
    bool fLockNow = false;
    CRITICAL_BLOCK(cs_chat)
        fLockNow = g_fUnlocked && g_lock.IsLocked(GetTime());
    if (!fLockNow)
        return false;
    printf("btfchat: locking after %d minutes of inactivity\n",
           (int)(LOCK_AFTER_SECONDS / 60));
    ChatLock();
    return true;
}

int64_t ChatSecondsBeforeLock()
{
    CRITICAL_BLOCK(cs_chat)
        return g_fUnlocked ? g_lock.SecondsLeft(GetTime()) : 0;
    return 0;
}

// ---- reading ---------------------------------------------------------------

void ChatPendingInvites(std::vector<Invite>& out)
{
    out.clear();
    CRITICAL_BLOCK(cs_chat)
        if (g_fUnlocked)
            g_roster.Pending(out);
}

void ChatContacts(std::vector<std::string>& out)
{
    out.clear();
    CRITICAL_BLOCK(cs_chat)
        if (g_fUnlocked)
            g_roster.Accepted(out);
}

void ChatConversation(const std::string& peerAddr, std::vector<LogEntry>& out)
{
    out.clear();
    CRITICAL_BLOCK(cs_chat)
        if (g_fUnlocked)
            g_history.Conversation(peerAddr, out);
}

PeerState ChatPeerState(const std::string& peerAddr)
{
    CRITICAL_BLOCK(cs_chat)
        return g_fUnlocked ? g_roster.State(peerAddr) : PEER_UNKNOWN;
    return PEER_UNKNOWN;
}

// ---- outbound --------------------------------------------------------------

// Resolve, dial, handshake, hand over one frame, close. One Tor circuit per
// message: expensive, and the simplest thing that is correct. A connection pool
// belongs here once this is proven on a real network.
// ---- outbound connections --------------------------------------------------
//
// One conversation, one connection, kept open.
//
// It used to be a connection per message: resolve, build a Tor circuit, shake
// hands, send one frame, hang up. Correct, simple, and five to thirty seconds of
// "sending over Tor..." on every single line -- which is what the first working
// two-way test felt like. Only the first message of a conversation should pay
// for the circuit.
//
// Keeping it open is also better cryptographically, not just faster: the frames
// stay inside one btfchan session, so the per-message ratchet keeps advancing
// instead of restarting from a fresh handshake each time.
//
// What an idle open circuit costs is a circuit held open, which is a thing a
// watcher can see lasting. So it is not held forever: POOL_IDLE_SECONDS of
// silence and it is dropped, and the next message pays for a new one.
static const int64_t POOL_IDLE_SECONDS = 5 * 60;

struct OutLink
{
    btf_socket_t sock;
    Link         link;
    int64_t      nLastUsed;
    OutLink() : sock(INVALID_SOCKET), nLastUsed(0) {}
};

// Its own lock, not cs_chat: dialling holds this for as long as Tor takes, and
// the interface asks cs_chat questions every frame. Sharing one lock would
// freeze the window for the length of a circuit.
static CCriticalSection cs_pool;
static std::map<std::string, OutLink*> g_mapOutLinks;

static void DropOutLink(std::map<std::string, OutLink*>::iterator it)
{
    it->second->link.Close();
    if (it->second->sock != INVALID_SOCKET)
        closesocket(it->second->sock);
    delete it->second;
    g_mapOutLinks.erase(it);
}

// Close every pooled connection. Called when the session locks: the links carry
// session keys, and a locked chat must not be holding live channels open.
static void CloseAllOutLinks()
{
    CRITICAL_BLOCK(cs_pool)
        while (!g_mapOutLinks.empty())
            DropOutLink(g_mapOutLinks.begin());
}

// Drop what has gone quiet. An open Tor circuit that nobody is using is a
// circuit somebody could be watching for no benefit.
static void ReapIdleOutLinks(int64_t nNow)
{
    CRITICAL_BLOCK(cs_pool)
    {
        for (std::map<std::string, OutLink*>::iterator it = g_mapOutLinks.begin();
             it != g_mapOutLinks.end(); )
        {
            if (nNow - it->second->nLastUsed > POOL_IDLE_SECONDS)
            {
                std::map<std::string, OutLink*>::iterator dead = it++;
                printf("btfchat: closing an idle connection\n");
                DropOutLink(dead);
            }
            else
                ++it;
        }
    }
}

// Resolve, dial and shake hands. Returns a live OutLink or NULL with a reason.
static OutLink* DialPeer(const std::string& peerAddr, std::string& errOut)
{
    unsigned char peerPub[32];
    int nVer = 0;
    if (!btf::ParseAddressVersion(peerAddr, peerPub, nVer))
    {
        errOut = "that is not a .btf address";
        return NULL;
    }
    if (nVer != btf::ADDR_VERSION_XONLY)
    {
        errOut = "that address uses a version this build cannot talk to";
        return NULL;
    }

    std::string onion;
    unsigned char encPub[32];
    if (!NetResolve(peerAddr, onion, encPub, errOut) || onion.empty())
    {
        // Either nothing is published for that address or no node could be
        // asked. From here the two are the same thing: no way to reach them
        // right now. NetResolve's reason says which.
        if (errOut.empty())
            errOut = "could not find that address on the Bitflash network";
        return NULL;
    }

    btf_socket_t sock = INVALID_SOCKET;
    if (!ChatDialOnion(onion, 30, sock, errOut))
        return NULL;

    OutLink* out = new OutLink;
    out->sock = sock;
    SocketStream stream(sock);
    // encPub is the key the peer's SIGNED descriptor names, so the handshake
    // authenticates them. A key from anywhere else would make this encryption
    // with no authentication.
    if (!out->link.ConnectAsClient(stream, encPub, errOut))
    {
        out->link.Close();
        closesocket(sock);
        delete out;
        return NULL;
    }
    out->nLastUsed = GetTime();
    return out;
}

static bool SendOneFrame(const std::string& peerAddr, const std::string& frameJson,
                         std::string& errOut)
{
    errOut.clear();

    CRITICAL_BLOCK(cs_pool)
    {
        std::map<std::string, OutLink*>::iterator it = g_mapOutLinks.find(peerAddr);
        if (it != g_mapOutLinks.end())
        {
            SocketStream stream(it->second->sock);
            if (it->second->link.SendFrame(stream, frameJson, errOut))
            {
                it->second->nLastUsed = GetTime();
                return true;
            }
            // The other end went away, or Tor dropped the circuit under us.
            // Neither is an error worth showing: dial again and try once more,
            // which is what a person would do without being told.
            printf("btfchat: the open connection died, dialling again\n");
            DropOutLink(it);
        }

        OutLink* fresh = DialPeer(peerAddr, errOut);
        if (!fresh)
            return false;

        SocketStream stream(fresh->sock);
        if (!fresh->link.SendFrame(stream, frameJson, errOut))
        {
            fresh->link.Close();
            closesocket(fresh->sock);
            delete fresh;
            return false;
        }
        fresh->nLastUsed = GetTime();
        g_mapOutLinks[peerAddr] = fresh;
        return true;
    }
    errOut = "the connection pool is unavailable";
    return false;
}

bool ChatInvite(const std::string& peerAddr, const std::string& note, std::string& errOut)
{
    errOut.clear();
    if (!ChatUnlocked()) { errOut = "the chat is locked"; return false; }

    Identity id;
    CRITICAL_BLOCK(cs_chat)
    {
        if (peerAddr == g_id.address)
        {
            errOut = "that is your own address";
            return false;
        }
        // Recorded before the dial: a dial that dies halfway must not leave us
        // believing we never asked, or the peer's answer would have nowhere to
        // land.
        //
        // But "already recorded" must not mean "cannot try again". The first
        // attempt fails routinely -- the other side may not have published yet --
        // and refusing the retry left the user stuck at "invite already sent"
        // with no way forward, which is what happened on the first real run.
        // Re-sending is safe: their gate takes one invite and ignores the rest.
        if (g_roster.State(peerAddr) != PEER_INVITE_OUT &&
            !g_roster.NoteOutgoingInvite(peerAddr, GetTime(), errOut))
            return false;
        SaveStore();
        id = g_id;
    }

    Frame f;
    f.kind = MSG_INVITE;
    f.sent = GetTime();
    f.text = note.size() > MAX_INVITE_NOTE ? note.substr(0, MAX_INVITE_NOTE) : note;
    std::string js;
    bool fOk = SignFrame(g_secp, id, f, js, errOut) && SendOneFrame(peerAddr, js, errOut);
    IdentityClear(id);
    return fOk;
}

bool ChatAcceptInvite(const std::string& peerAddr, std::string& errOut)
{
    errOut.clear();
    if (!ChatUnlocked()) { errOut = "the chat is locked"; return false; }

    Identity id;
    CRITICAL_BLOCK(cs_chat)
    {
        if (!g_roster.AcceptInvite(peerAddr, errOut))
            return false;
        SaveStore();
        id = g_id;
    }

    Frame f;
    f.kind = MSG_INVITE_ACCEPT;
    f.sent = GetTime();
    std::string js;
    bool fOk = SignFrame(g_secp, id, f, js, errOut) && SendOneFrame(peerAddr, js, errOut);
    IdentityClear(id);
    // The accept is recorded locally either way: if the notification did not
    // reach them, their next message still arrives, because we are the side that
    // had to consent.
    if (!fOk)
        errOut = "accepted here, but could not tell them: " + errOut;
    return true;
}

bool ChatDeclineInvite(const std::string& peerAddr, std::string& errOut)
{
    errOut.clear();
    if (!ChatUnlocked()) { errOut = "the chat is locked"; return false; }
    CRITICAL_BLOCK(cs_chat)
    {
        if (!g_roster.DeclineInvite(peerAddr, errOut))
            return false;
        SaveStore();
    }
    // Nothing is sent. Silence tells the other side less than a refusal does.
    return true;
}

bool ChatBlock(const std::string& peerAddr, std::string& errOut)
{
    errOut.clear();
    if (!ChatUnlocked()) { errOut = "the chat is locked"; return false; }
    CRITICAL_BLOCK(cs_chat)
    {
        if (!g_roster.Block(peerAddr, errOut))
            return false;
        SaveStore();
    }
    return true;
}

// Seal one frame to a peer's published epoch keys and leave it under the tag
// the two of us share for that epoch. Returns false with a reason the interface
// can show; "they published no epoch keys" is the ordinary case for somebody who
// has never opened the chat.
// The peer's STATIC channel key, the one their signed descriptor names.
//
// The mailbox tag has to be computed from the two static keys and nothing else,
// because it is the only pair of keys both sides can agree on without asking
// each other anything. Getting this wrong does not fail loudly: the sender posts
// under a name nobody is listening to, reports success, and the message is
// simply never collected. It is worth its own function so that both sides ask
// the same question.
static bool ResolvePeerStaticChanKey(const std::string& peerAddr,
                                     unsigned char out[btf::CHAN_KEYBYTES],
                                     std::string& errOut)
{
    std::string onion;
    return NetResolve(peerAddr, onion, out, errOut);
}

static bool LeaveInMailbox(const std::string& peerAddr, const Identity& id,
                           const std::string& frameJson, std::string& errOut)
{
    errOut.clear();

    std::string ann;
    if (!NetQueryEpochKeys(peerAddr, ann, errOut))
        return false;

    int64_t nEpoch = 0;
    unsigned char their_x[btf::CHAN_KEYBYTES];
    unsigned char their_kem[btf::CHAN_KEM_PUBBYTES];
    // Verified against the address we asked for, not the one the answer claims:
    // otherwise a node hands back somebody else's valid announcement and the
    // conversation gets sealed to a stranger.
    if (!VerifyEpochKeys(g_secp, peerAddr, ann, GetTime(), nEpoch, their_x, their_kem, errOut))
        return false;

    std::vector<unsigned char> env;
    if (!SealEnvelope(their_x, their_kem, frameJson, env, errOut))
        return false;

    // The envelope is sealed to their EPOCH keys, which is what makes an old
    // message unopenable once those are destroyed. The tag it is filed under is
    // a different question, and the answer is the two STATIC keys.
    //
    // This used to pass their_x -- the epoch key -- to MailboxTag, while the
    // collecting side used the static key from their descriptor. Two names for
    // one mailbox: the sender filed the message, said "left in their mailbox",
    // and the recipient looked under a name nothing was ever filed under. The
    // comment here said static; the code said epoch; the comment was right.
    unsigned char their_static[btf::CHAN_KEYBYTES];
    if (!ResolvePeerStaticChanKey(peerAddr, their_static, errOut))
        return false;

    std::string tag;
    if (!MailboxTag(id.chan_sk, their_static, nEpoch, tag))
    {
        errOut = "could not derive the mailbox tag";
        return false;
    }
    return NetPostEnvelope(tag, env, errOut);
}

// Sign one frame and get it to the peer: directly, else their mailbox, else
// our own queue. Shared by every kind a person sends in a conversation, so a
// payment note travels exactly the way a message does. `text` is what the
// queue shows while it waits.
static bool SendInConversation(const std::string& peerAddr, Frame& f, const std::string& text,
                               bool& fLeftInMailboxOut, std::string& errOut)
{
    fLeftInMailboxOut = false;
    errOut.clear();
    if (!ChatUnlocked()) { errOut = "the chat is locked"; return false; }

    Identity id;
    CRITICAL_BLOCK(cs_chat)
    {
        if (g_roster.State(peerAddr) != PEER_ACCEPTED)
        {
            errOut = "you have no accepted conversation with that address";
            return false;
        }
        id = g_id;
    }

    f.sent = GetTime();
    std::string js;
    if (!SignFrame(g_secp, id, f, js, errOut))
    {
        IdentityClear(id);
        return false;
    }
    bool fOk = SendOneFrame(peerAddr, js, errOut);
    bool fQueued = false;
    if (!fOk)
    {
        // Offline, unreachable, or Tor having a bad minute. Leave it where they
        // will find it. The live error is kept: if the mailbox fails too, the
        // user should see why the first attempt failed, not only the second.
        std::string strLive = errOut;
        std::string strBox;
        if (LeaveInMailbox(peerAddr, id, js, strBox))
        {
            fOk = true;
            fLeftInMailboxOut = true;
            errOut.clear();
        }
        else
        {
            // Nobody else will hold it, so we hold it. The frame is already
            // signed, so what goes in the queue is exactly what would have gone
            // on the wire -- retrying is sending the same message, not writing a
            // new one with a new timestamp.
            Pending p;
            p.peer      = peerAddr;
            p.frameJson = js;
            p.id        = f.id;
            p.text      = text;
            p.sent      = f.sent;

            std::string strQueue;
            CRITICAL_BLOCK(cs_chat)
                fQueued = g_outbox.Add(p, strQueue);

            if (fQueued)
                errOut = "they are not reachable -- kept here and sent when they come back "
                         "(within a day, after that it expires)";
            else
                errOut = "could not connect (" + strLive + "), could not leave a message ("
                         + strBox + "), and could not keep it here (" + strQueue + ")";
        }
    }
    IdentityClear(id);

    // Only recorded once it is actually gone. A line in the history that never
    // left is a lie the user acts on -- which is why a queued message does NOT
    // go in here. It is shown from the queue, marked as still waiting, and moves
    // into the history on the day it actually leaves.
    if (fOk)
        CRITICAL_BLOCK(cs_chat)
        {
            std::string e;
            g_history.Append(f, peerAddr, true, e);
            SaveStore();
        }
    else if (fQueued)
    {
        CRITICAL_BLOCK(cs_chat)
            SaveStore();
        // Queued counts as taken. The caller's false would put the text back in
        // the box for the user to send again, and they would be sending a second
        // copy of something already waiting to go.
        return true;
    }
    return fOk;
}

bool ChatSendText(const std::string& peerAddr, const std::string& text,
                  bool& fLeftInMailboxOut, std::string& errOut)
{
    fLeftInMailboxOut = false;
    errOut.clear();
    if (text.empty()) { errOut = "nothing to send"; return false; }
    if (text.size() > MAX_TEXT_BYTES) { errOut = "that message is too long"; return false; }
    Frame f;
    f.kind = MSG_TEXT;
    f.text = text;
    return SendInConversation(peerAddr, f, text, fLeftInMailboxOut, errOut);
}

bool ChatShareAddress(const std::string& peerAddr, int64_t nRequested, const std::string& note,
                      bool& fLeftInMailboxOut, std::string& errOut)
{
    fLeftInMailboxOut = false;
    errOut.clear();
    if (note.size() > MAX_PAY_NOTE) { errOut = "that note is too long"; return false; }
    // A fresh address from the person's own wallet each time: one per request
    // keeps their payments from being linked to each other on the chain.
    std::string addr;
    if (!WalletNewAddress(addr, errOut))
        return false;
    Frame f;
    f.kind = MSG_PAY_ADDRESS;
    f.payTo = addr;
    f.amount = nRequested;
    f.text = note;
    std::string shown = nRequested > 0
        ? strprintf("asked for %s BTF", FormatMoney(nRequested).c_str())
        : std::string("shared an address to be paid at");
    return SendInConversation(peerAddr, f, shown, fLeftInMailboxOut, errOut);
}

bool ChatPeerPayAddress(const std::string& peerAddr, std::string& addrOut, int64_t& nRequestedOut)
{
    addrOut.clear();
    nRequestedOut = 0;
    std::vector<LogEntry> v;
    CRITICAL_BLOCK(cs_chat)
    {
        if (!g_fUnlocked)
            return false;
        g_history.Conversation(peerAddr, v);
    }
    // The newest address THEY signed. Never one of ours, never one typed in:
    // the signature on the frame is the whole reason this is safe to pay.
    for (size_t i = v.size(); i-- > 0; )
        if (v[i].kind == MSG_PAY_ADDRESS && !v[i].outgoing && v[i].from == peerAddr && !v[i].payTo.empty())
        {
            addrOut = v[i].payTo;
            nRequestedOut = v[i].amount;
            return true;
        }
    return false;
}

// ---- public communities ---------------------------------------------------------

bool ChatCommunityJoin(const std::string& keyHex, const std::string& name, std::string& idOut,
                       std::string& errOut)
{
    errOut.clear();
    idOut.clear();
    if (!ChatUnlocked()) { errOut = "the chat is locked"; return false; }
    if (keyHex.size() != 64 || !IsHex(keyHex)) { errOut = "a community key is 64 hex characters"; return false; }
    if (!community::NameOk(name)) { errOut = "a community name is 1 to 32 letters, digits, - or _"; return false; }
    JoinedCommunity c;
    c.key = ParseHex(keyHex);
    c.name = name;
    idOut = community::IdHex(&c.key[0]);
    CRITICAL_BLOCK(cs_chat)
    {
        if (g_communities.size() >= 256 && !g_communities.count(idOut))
        {
            errOut = "you are in 256 communities already";
            return false;
        }
        g_communities[idOut] = c;
        SaveStore();
    }
    return true;
}

bool ChatCommunityLeave(const std::string& id, std::string& errOut)
{
    errOut.clear();
    CRITICAL_BLOCK(cs_chat)
    {
        if (!g_communities.erase(id))
        {
            errOut = "you are not in that community";
            return false;
        }
        SaveStore();
    }
    return true;
}

bool ChatCommunityCreatePublic(const std::string& name, std::string& txidOut, std::string& idOut,
                               std::string& errOut)
{
    errOut.clear();
    txidOut.clear();
    if (!ChatUnlocked()) { errOut = "the chat is locked"; return false; }
    if (!community::NameOk(name)) { errOut = "a community name is 1 to 32 letters, digits, - or _"; return false; }
    unsigned char key[community::KEY_BYTES];
    randombytes_buf(key, sizeof(key));
    std::vector<unsigned char> data = community::ListingData(key, name);
    // The listing is permanent and public from here: name and key in a block,
    // paid for from the person's own wallet.
    if (!WalletBurn(community::MIN_BURN, HexStr(data.begin(), data.end(), false), txidOut, errOut))
        return false;
    return ChatCommunityJoin(HexStr(key, key + sizeof(key), false), name, idOut, errOut);
}

void ChatCommunities(std::vector<std::pair<std::string, std::string> >& out)
{
    out.clear();
    CRITICAL_BLOCK(cs_chat)
        for (std::map<std::string, JoinedCommunity>::const_iterator it = g_communities.begin();
             it != g_communities.end(); ++it)
            out.push_back(std::make_pair(it->first, it->second.name));
}

// A post or a swap offer, sealed under the community key and left with the
// nodes under today's tag.
static bool PostToCommunity(const std::string& id, MsgKind kind, const std::string& text, std::string& errOut)
{
    errOut.clear();
    if (!ChatUnlocked()) { errOut = "the chat is locked"; return false; }
    if (text.empty() || text.size() > MAX_TEXT_BYTES) { errOut = "a post is 1 to 4096 bytes"; return false; }
    JoinedCommunity c;
    Identity me;
    CRITICAL_BLOCK(cs_chat)
    {
        std::map<std::string, JoinedCommunity>::const_iterator it = g_communities.find(id);
        if (it == g_communities.end()) { errOut = "you are not in that community"; return false; }
        c = it->second;
        me = g_id;
    }
    Frame f;
    f.kind = kind;
    f.group = id;
    f.sent = GetTime();
    f.text = text;
    std::string js;
    bool fSigned = SignFrame(g_secp, me, f, js, errOut);
    IdentityClear(me);
    if (!fSigned)
        return false;
    std::vector<unsigned char> env;
    if (!community::Seal(&c.key[0], js, env))
    {
        errOut = "sealing the post failed";
        return false;
    }
    if (!NetPostEnvelope(community::TagHex(&c.key[0], MailboxEpoch(f.sent)), env, errOut))
        return false;
    CRITICAL_BLOCK(cs_chat)
    {
        std::string e;
        g_history.Append(f, std::string(), true, e);
        SaveStore();
    }
    return true;
}

bool ChatCommunityPost(const std::string& id, const std::string& text, std::string& errOut)
{
    return PostToCommunity(id, MSG_GROUP_TEXT, text, errOut);
}

bool ChatCommunityPostOffer(const std::string& id, const std::string& offerText, std::string& errOut)
{
    return PostToCommunity(id, MSG_SWAP_OFFER, offerText, errOut);
}

bool ChatSendSwapStep(const std::string& peerAddr, const std::string& stepText,
                      bool& fLeftInMailboxOut, std::string& errOut)
{
    Frame f;
    f.kind = MSG_SWAP;
    f.text = stepText;
    return SendInConversation(peerAddr, f, stepText, fLeftInMailboxOut, errOut);
}

void ChatSaveStore()
{
    CRITICAL_BLOCK(cs_chat)
        SaveStore();
}

void ChatCommunityLog(const std::string& id, std::vector<LogEntry>& out)
{
    out.clear();
    CRITICAL_BLOCK(cs_chat)
        if (g_fUnlocked)
            g_history.GroupLog(id, out);
}

bool ChatCommunityDirectory(std::vector<CChatListing>& out, std::string& errOut)
{
    return NetDirectory(out, errOut);
}

bool ChatPay(const std::string& peerAddr, int64_t nAmount, const std::string& note,
             std::string& txidOut, bool& fLeftInMailboxOut, std::string& errOut)
{
    txidOut.clear();
    fLeftInMailboxOut = false;
    errOut.clear();
    if (nAmount <= 0) { errOut = "nothing to pay"; return false; }
    if (note.size() > MAX_PAY_NOTE) { errOut = "that note is too long"; return false; }
    std::string addr;
    int64_t nRequested = 0;
    if (!ChatPeerPayAddress(peerAddr, addr, nRequested))
    {
        errOut = "they have not shared an address to be paid at yet -- ask them to";
        return false;
    }
    if (!WalletPay(addr, nAmount, txidOut, errOut))
        return false;

    // The money has moved. Telling them is a courtesy now, not the payment:
    // if this note never arrives, the coins are still theirs on the chain.
    Frame f;
    f.kind = MSG_PAYMENT;
    f.payTo = addr;
    f.amount = nAmount;
    f.txid = txidOut;
    f.text = note;
    std::string err2;
    if (!SendInConversation(peerAddr, f, strprintf("paid %s BTF", FormatMoney(nAmount).c_str()),
                            fLeftInMailboxOut, err2))
        errOut = "paid (" + txidOut + "), but could not tell them: " + err2;
    return true;
}

// Send what is waiting for one peer, oldest first.
//
// Direct only: the mailbox was already tried once when the message was written,
// and retrying it here would mean every queued message costs a round of node
// connections, and a second of work, every couple of minutes. The queue exists for the case where no
// third party will hold anything, so it delivers the way this build delivers --
// their onion, our connection.
//
// Stops at the first failure, so what arrives arrives in the order it was
// written. Returns how many went.
static int FlushOutboxFor(const std::string& peerAddr)
{
    std::vector<Pending> waiting;
    CRITICAL_BLOCK(cs_chat)
    {
        if (!g_fUnlocked)
            return 0;
        g_outbox.For(peerAddr, waiting);
    }
    if (waiting.empty())
        return 0;

    int nSent = 0;
    for (size_t i = 0; i < waiting.size() && !fShutdown; i++)
    {
        std::string err;
        if (!SendOneFrame(peerAddr, waiting[i].frameJson, err))
            break;

        Frame f;
        std::string e;
        // Re-read our own frame rather than trusting what we stored: the store
        // is a file, and a file is something else could have edited.
        if (!OpenFrame(g_secp, waiting[i].frameJson, f, e))
        {
            CRITICAL_BLOCK(cs_chat)
                g_outbox.Remove(waiting[i].id);
            continue;
        }
        CRITICAL_BLOCK(cs_chat)
        {
            g_history.Append(f, peerAddr, true, e);
            g_outbox.Remove(waiting[i].id);
        }
        nSent++;
    }

    if (nSent > 0)
        CRITICAL_BLOCK(cs_chat)
            SaveStore();
    return nSent;
}

// Everything waiting, for everybody, plus the ones that can no longer arrive.
static int FlushOutbox()
{
    std::vector<std::string> peers;
    int nExpired = 0;
    CRITICAL_BLOCK(cs_chat)
    {
        if (!g_fUnlocked)
            return 0;
        nExpired = g_outbox.Expire(GetTime());
        g_outbox.Peers(peers);
    }
    if (nExpired > 0)
    {
        printf("btfchat: %d queued message(s) expired undelivered (older than a day)\n", nExpired);
        CRITICAL_BLOCK(cs_chat)
            SaveStore();
    }

    int nSent = 0;
    for (size_t i = 0; i < peers.size() && !fShutdown; i++)
        nSent += FlushOutboxFor(peers[i]);
    return nSent;
}

bool ChatPendingFor(const std::string& peerAddr, std::vector<Pending>& out)
{
    out.clear();
    CRITICAL_BLOCK(cs_chat)
    {
        if (!g_fUnlocked)
            return false;
        g_outbox.For(peerAddr, out);
        return true;
    }
    return false;
}

// ---- inbound ---------------------------------------------------------------

struct ServeArg
{
    btf_socket_t sock;
};

static void ThreadChatServe(void* parg)
{
    // This macro has to be the FIRST statement, before anything touches parg.
    // It sometimes re-calls this function and returns, so only the innermost
    // call does the real work -- and the argument has to still be alive when it
    // does. With `delete arg` above it, the recursive call read a freed pointer
    // and deleted it again: a use-after-free and a double free on almost every
    // inbound connection, because the macro recurses up to 49 times out of 50.
    //
    // It showed up as the receiving side simply vanishing the moment somebody
    // dialled it, while the dialler sat there saying "no flight 2 from the other
    // side". Found on the first real connection between two instances.
    IMPLEMENT_RANDOMIZE_STACK(ThreadChatServe(parg));

    ServeArg* arg = (ServeArg*)parg;
    btf_socket_t sock = arg->sock;
    delete arg;

    try
    {
        unsigned char chan_sk[32];
        bool fHave = false;
        CRITICAL_BLOCK(cs_chat)
            if (g_fUnlocked)
            {
                memcpy(chan_sk, g_id.chan_sk, 32);
                fHave = true;
            }
        if (!fHave)
        {
            // Locked: nothing to answer a handshake with, and nothing to leak.
            closesocket(sock);
            return;
        }

        // Plain printf, not LogPrint: when a connection arrives and nothing
        // visible happens, the first question is always "did it even reach the
        // other side", and needing -debug to answer it wastes a round trip with
        // the person testing.
        printf("btfchat: inbound connection accepted\n");

        SocketStream stream(sock);
        Link link;
        std::string err;
        bool fOk = link.AcceptAsEndpoint(stream, chan_sk, err);
        sodium_memzero(chan_sk, sizeof(chan_sk));
        if (!fOk)
        {
            LogPrint("btfchat", "btfchat: handshake refused: %s\n", err.c_str());
            link.Close();
            closesocket(sock);
            return;
        }

        printf("btfchat: inbound handshake complete\n");

        // The dialler proved nothing about itself in the handshake -- it
        // authenticated US. Who it is comes from the first frame's signature, and
        // from then on every frame on this connection has to come from that same
        // address: otherwise one peer could hand over another's frames and choose
        // when they appear to speak.
        std::string peer;

        while (!fShutdown && link.IsOpen())
        {
            std::string js;
            if (!link.RecvFrame(stream, js, err))
                break;

            Inbox inbox;
            Frame f;
            bool fDelivered = false;
            std::string reason;
            CRITICAL_BLOCK(cs_chat)
            {
                if (!g_fUnlocked)
                    break;
                inbox.secpctx = g_secp;
                inbox.myAddress = g_id.address;
                inbox.roster = &g_roster;
                inbox.replay = &g_replay;
                inbox.history = &g_history;
                fDelivered = inbox.Deliver(js, peer, GetTime(), f, reason);
                if (fDelivered)
                    SaveStore();
            }

            if (fDelivered)
            {
                printf("btfchat: delivered a frame from %s\n", f.from.c_str());
                // They just wrote to us, so they are up right now. If we are
                // holding anything for them, this is the moment -- not two
                // minutes from now. Flagged rather than sent from here: dialling
                // out from the thread that is serving an inbound connection
                // would hold that connection open for the length of a circuit.
                g_fFlushOutbox = true;
            }

            if (!fDelivered)
            {
                // Logged, never answered. Telling a stranger why they were
                // refused is telling them which addresses exist and which are
                // blocked.
                LogPrint("btfchat", "btfchat: frame refused: %s\n", reason.c_str());
                continue;
            }
            if (peer.empty())
                peer = f.from;
        }

        link.Close();
        closesocket(sock);
    }
    catch (std::exception& e)
    {
        PrintException(&e, "ThreadChatServe()");
        closesocket(sock);
    }
    catch (...)
    {
        PrintException(NULL, "ThreadChatServe()");
        closesocket(sock);
    }
}

static void ThreadChatListener(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadChatListener(parg));
    try
    {
        while (!fShutdown)
        {
            btf_socket_t sock = accept(g_listener, NULL, NULL);
            if (sock == INVALID_SOCKET)
            {
                if (fShutdown)
                    break;
                Sleep(200);
                continue;
            }
            ServeArg* arg = new ServeArg;
            arg->sock = sock;
            if (_beginthread(ThreadChatServe, 0, arg) == -1)
            {
                printf("btfchat: could not start a serve thread\n");
                delete arg;
                closesocket(sock);
            }
        }
    }
    catch (std::exception& e) { PrintException(&e, "ThreadChatListener()"); }
    catch (...)               { PrintException(NULL, "ThreadChatListener()"); }

    CRITICAL_BLOCK(cs_chat)
        g_fListening = false;
    printf("btfchat: listener stopped\n");
}

// How far back each poll asks again. See where g_mapPolledUntil is updated.
static const int64_t MAILBOX_REPOLL_WINDOW = 30 * 60;

// How often our own epoch keys and descriptor go out again when nothing has
// changed. Nodes keep them for days and hand them to each other; this only
// covers the ones that restarted in the meantime.
static const int64_t EPOCH_REPUBLISH_SECS = 6 * 60 * 60;
static const int DESCRIPTOR_REPUBLISH_SECS = 6 * 60 * 60;

// True the first time a given envelope is seen. Bounded: past the cap the
// oldest memory goes, and the worst that does is open one envelope twice --
// which the replay guard then refuses.
static bool FirstSightOfEnvelope(const std::vector<unsigned char>& env)
{
    static CCriticalSection cs_seen;
    static std::set<std::string> setSeen;
    static std::deque<std::string> qSeen;
    unsigned char h[32];
    crypto_hash_sha256(h, env.empty() ? NULL : &env[0], env.size());
    std::string k((const char*)h, 32);
    CRITICAL_BLOCK(cs_seen)
    {
        if (!setSeen.insert(k).second)
            return false;
        qSeen.push_back(k);
        while (qSeen.size() > 4096)
        {
            setSeen.erase(qSeen.front());
            qSeen.pop_front();
        }
    }
    return true;
}

// Open and record community posts collected under one community's tag. A post
// is a group frame whose group is the community id, signed by whoever wrote
// it; it is refused if the signature fails, if it names another community, if
// its author is somebody we blocked, or if it is a replay.
static int DeliverCommunityPosts(const std::vector<unsigned char>& key,
                                 const std::vector<std::vector<unsigned char> >& envs, int64_t nNow)
{
    std::string id = community::IdHex(&key[0]);
    int n = 0;
    for (size_t k = 0; k < envs.size(); k++)
    {
        if (!FirstSightOfEnvelope(envs[k]))
            continue;
        std::string js;
        if (!community::Open(&key[0], envs[k], js))
            continue;
        Frame f;
        std::string err;
        if (!OpenFrame(g_secp, js, f, err))
            continue;
        if ((f.kind != MSG_GROUP_TEXT && f.kind != MSG_SWAP_OFFER) || f.group != id)
            continue;
        CRITICAL_BLOCK(cs_chat)
        {
            if (!g_fUnlocked || g_roster.IsBlocked(f.from))
                break;
            if (!g_replay.Accept(f, nNow, err))
                break;
            // Our own posts come back too; the history knows the id already.
            if (g_history.Append(f, std::string(), f.from == g_id.address, err))
            {
                n++;
                SaveStore();
            }
        }
    }
    return n;
}

int ChatPollMailboxes(std::string& errOut)
{
    errOut.clear();
    if (!ChatUnlocked())
    {
        errOut = "the chat is locked";
        return 0;
    }

    Identity id;
    std::vector<std::string> contacts;
    CRITICAL_BLOCK(cs_chat)
    {
        if (!g_fUnlocked)
        {
            errOut = "the chat is locked";
            return 0;
        }
        id = g_id;
        g_roster.Accepted(contacts);
    }

    int64_t nNow = GetTime();
    int64_t nEpochNow = MailboxEpoch(nNow);
    int nDelivered = 0;

    // Every tag we share with every contact, this epoch and the previous one --
    // a message left at 23:59 is collected at 00:01, and MAILBOX_KEEP_EPOCHS is
    // what makes both openable. All of them go to the network in one round:
    // each round is a Tor circuit to a node, and asking per tag would be a
    // circuit per contact per epoch, which is both slow and countable.
    std::vector<std::pair<std::string, int64_t> > vTagSince;
    for (size_t i = 0; i < contacts.size() && !fShutdown; i++)
    {
        // The static key comes from the contact's descriptor, and is cached:
        // asking the network again every two minutes would teach it nothing.
        unsigned char their_pub[btf::CHAN_KEYBYTES];
        std::string errResolve;
        if (!ResolvePeerStaticChanKey(contacts[i], their_pub, errResolve))
            continue;

        for (int back = 0; back < (int)MAILBOX_KEEP_EPOCHS; back++)
        {
            std::string tag;
            if (!MailboxTag(id.chan_sk, their_pub, nEpochNow - back, tag))
                break;
            int64_t nSince = 0;
            CRITICAL_BLOCK(cs_chat)
            {
                std::map<std::string, int64_t>::const_iterator it = g_mapPolledUntil.find(tag);
                if (it != g_mapPolledUntil.end())
                    nSince = it->second;
            }
            vTagSince.push_back(std::make_pair(tag, nSince));
        }
    }

    // The communities we joined ride in the same round: their tags are
    // computed from the key, today's and yesterday's, and their posts are
    // opened with the key instead of our mailbox keys.
    std::map<std::string, std::vector<unsigned char> > mapCommunityTag;   // tag -> key
    CRITICAL_BLOCK(cs_chat)
        for (std::map<std::string, JoinedCommunity>::const_iterator it = g_communities.begin();
             it != g_communities.end(); ++it)
            for (int back = 0; back < 2; back++)
            {
                std::string tag = community::TagHex(&it->second.key[0], nEpochNow - back);
                int64_t nSince = 0;
                std::map<std::string, int64_t>::const_iterator p = g_mapPolledUntil.find(tag);
                if (p != g_mapPolledUntil.end())
                    nSince = p->second;
                vTagSince.push_back(std::make_pair(tag, nSince));
                mapCommunityTag[tag] = it->second.key;
            }

    std::map<std::string, std::vector<std::vector<unsigned char> > > mapEnvs;
    std::string errFetch;
    if (vTagSince.empty() || !NetFetchEnvelopes(vTagSince, mapEnvs, errFetch))
    {
        if (!errFetch.empty())
            LogPrint("btfchat", "btfchat: mailbox not collected: %s\n", errFetch.c_str());
        IdentityClear(id);
        return 0;
    }

    for (size_t t = 0; t < vTagSince.size() && !fShutdown; t++)
    {
        const std::string& tag = vTagSince[t].first;
        std::map<std::string, std::vector<unsigned char> >::const_iterator ck = mapCommunityTag.find(tag);
        if (ck != mapCommunityTag.end())
        {
            nDelivered += DeliverCommunityPosts(ck->second, mapEnvs[tag], nNow);
            CRITICAL_BLOCK(cs_chat)
                g_mapPolledUntil[tag] = nNow - MAILBOX_REPOLL_WINDOW;
            continue;
        }
        {
            const std::vector<std::vector<unsigned char> >& envs = mapEnvs[tag];
            for (size_t k = 0; k < envs.size(); k++)
            {
                // Each envelope is asked for again for a while after it
                // arrives (see the window below); open it once.
                if (!FirstSightOfEnvelope(envs[k]))
                    continue;

                std::vector<unsigned char> plain;
                std::string e2;
                // Our own posts under the shared tag fail to open, which is
                // exactly how they get skipped: they were sealed to the other
                // side's keys, not ours.
                if (!g_mailbox.Open(&envs[k][0], envs[k].size(), plain, e2))
                    continue;

                std::string js((const char*)&plain[0], plain.size());
                Frame f;
                std::string reason;
                bool fDelivered = false;
                CRITICAL_BLOCK(cs_chat)
                {
                    if (!g_fUnlocked)
                        break;
                    Inbox inbox;
                    inbox.secpctx = g_secp;
                    inbox.myAddress = g_id.address;
                    inbox.roster = &g_roster;
                    inbox.replay = &g_replay;
                    inbox.history = &g_history;
                    // peer is empty on purpose: an envelope arrives with no
                    // connection behind it, so the signature is the only thing
                    // that says who wrote it -- and it is enough.
                    fDelivered = inbox.Deliver(js, std::string(), nNow, f, reason);
                    if (fDelivered)
                        SaveStore();
                }
                if (fDelivered)
                    nDelivered++;
                else
                    LogPrint("btfchat", "btfchat: mailbox frame refused: %s\n", reason.c_str());
            }

            // Not "until now": an envelope carries its sender's clock, and it
            // may reach the node we ask after we asked. Asking again for the
            // last half hour costs a few duplicates, which FirstSightOfEnvelope
            // drops, instead of a message nobody ever collects.
            CRITICAL_BLOCK(cs_chat)
                g_mapPolledUntil[tag] = nNow - MAILBOX_REPOLL_WINDOW;
        }
    }

    IdentityClear(id);
    return nDelivered;
}

// Collects what was left for us, and keeps our own epoch keys published so
// people have something to seal to.
static void ThreadChatMailbox(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadChatMailbox(parg));
    try
    {
        while (!fShutdown)
        {
            if (ChatUnlocked())
            {
                std::string err;
                // Rotation first: a new day needs new keys published before
                // anybody seals to the old ones.
                CRITICAL_BLOCK(cs_chat)
                    if (g_fUnlocked)
                        g_mailbox.Rotate(GetTime(), err);

                // Published when the epoch turns, and again every few hours in
                // case the nodes holding it restarted and forgot. Not every
                // round: each publish costs a second of work, and the nodes
                // already pass it to each other.
                static int64_t nPublishedEpoch = -1;
                static int64_t nPublishedAt = 0;
                int64_t nEpochNow = MailboxEpoch(GetTime());
                bool fDue = (nEpochNow != nPublishedEpoch) ||
                            (GetTime() - nPublishedAt > EPOCH_REPUBLISH_SECS);

                EpochKeys pub;
                Identity id;
                bool fHave = false;
                if (fDue)
                    CRITICAL_BLOCK(cs_chat)
                        if (g_fUnlocked)
                        {
                            pub.epoch = nEpochNow;
                            if (g_mailbox.PublicFor(pub.epoch, pub.x_pk, pub.kem_pk))
                            {
                                id = g_id;
                                fHave = true;
                            }
                        }
                if (fHave)
                {
                    std::string ann;
                    if (SignEpochKeys(g_secp, id, pub, ann, err))
                    {
                        if (NetPublishEpochKeys(id.address, ann, pub.epoch, err))
                        {
                            nPublishedEpoch = pub.epoch;
                            nPublishedAt = GetTime();
                        }
                        else
                            LogPrint("btfchat", "btfchat: epoch keys not published: %s\n",
                                     err.c_str());
                    }
                    IdentityClear(id);
                }
                EpochKeysClear(pub);

                ReapIdleOutLinks(GetTime());

                int n = ChatPollMailboxes(err);
                if (n > 0)
                    printf("btfchat: %d message(s) collected from the mailbox\n", n);

                g_fFlushOutbox = false;
                int nOut = FlushOutbox();
                if (nOut > 0)
                    printf("btfchat: %d message(s) sent from the outbox\n", nOut);
            }

            // Two minutes between full rounds. Polling harder buys latency for
            // somebody who is offline anyway, and every poll is a Tor circuit to
            // a node -- which is traffic a watcher can count.
            //
            // The queue is different: it costs one connection to somebody we
            // already know is up, and waiting two minutes to answer a person who
            // is typing at us right now would feel broken. So the wait is
            // interruptible, and only for the queue.
            for (int i = 0; i < 120 && !fShutdown; i++)
            {
                Sleep(1000);
                if (g_fFlushOutbox && ChatUnlocked())
                {
                    g_fFlushOutbox = false;
                    int nNow = FlushOutbox();
                    if (nNow > 0)
                        printf("btfchat: %d message(s) sent from the outbox\n", nNow);
                }
            }
        }
    }
    catch (std::exception& e) { PrintException(&e, "ThreadChatMailbox()"); }
    catch (...)               { PrintException(NULL, "ThreadChatMailbox()"); }
}

// Publishes the chat's descriptor on the Bitflash network and keeps it fresh.
// Signed by the chat key, never the node's, and sent over Tor like everything
// else the chat does, so nothing a node holds ties the two identities together.
static void ThreadChatPublish(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadChatPublish(parg));
    try
    {
        bool fEverPublished = false;
        bool fLastFailed = false;
        while (!fShutdown)
        {
            std::string onion = BtfManagedTorChatOnion();
            if (!onion.empty() && ChatUnlocked())
            {
                unsigned char sk[32], encpub[32];
                bool fHave = false;
                CRITICAL_BLOCK(cs_chat)
                    if (g_fUnlocked)
                    {
                        memcpy(sk, g_id.sign_sk, 32);
                        memcpy(encpub, g_id.chan_pk, 32);
                        fHave = true;
                    }
                if (fHave)
                {
                    std::string err;
                    std::string hex;
                    static const char* h = "0123456789abcdef";
                    for (int i = 0; i < 32; i++)
                    { hex += h[encpub[i] >> 4]; hex += h[encpub[i] & 0x0f]; }

                    if (NetPublishDescriptor(sk, hex, onion, err))
                    {
                        fEverPublished = true;
                        fLastFailed = false;
                        CRITICAL_BLOCK(cs_chat)
                            g_status = "reachable at " + onion;
                    }
                    else
                    {
                        fLastFailed = true;
                        CRITICAL_BLOCK(cs_chat)
                            g_status = "listening, not yet published: " + err;
                    }
                    sodium_memzero(sk, sizeof(sk));
                }
            }
            else if (onion.empty())
            {
                CRITICAL_BLOCK(cs_chat)
                    g_status = "waiting for the chat onion service";
            }

            // Hours once it is out there: the nodes keep a descriptor for a week
            // and pass it to each other, so this only covers nodes that
            // restarted. Ten seconds while the onion service does not exist yet
            // -- on a fresh start it takes a moment, and waiting long to notice
            // it now does would leave the user in front of a chat nobody can
            // reach with nothing on screen explaining why. A minute after a
            // failed publish: each try costs a second of work and a few Tor
            // circuits, and no node answering is not fixed by asking faster.
            int nWait = !fEverPublished && !fLastFailed ? 10
                      : fLastFailed                     ? 60
                      :                                   DESCRIPTOR_REPUBLISH_SECS;
            for (int i = 0; i < nWait && !fShutdown; i++)
                Sleep(1000);
        }
    }
    catch (std::exception& e) { PrintException(&e, "ThreadChatPublish()"); }
    catch (...)               { PrintException(NULL, "ThreadChatPublish()"); }
}

void ChatSetPort(unsigned short port)
{
    CRITICAL_BLOCK(cs_chat)
        g_chatPort = port;
    BtfSetManagedTorChatPort(port);
}

unsigned short ChatPort()
{
    CRITICAL_BLOCK(cs_chat)
        return g_chatPort;
    return 0;
}

bool ChatServiceRunning()
{
    CRITICAL_BLOCK(cs_chat)
        return g_fListening;
    return false;
}

std::string ChatServiceStatus()
{
    CRITICAL_BLOCK(cs_chat)
        return g_status;
    return std::string("off");
}

std::string ChatOnionEndpoint() { return BtfManagedTorChatOnion(); }

bool ChatServiceStart(std::string& errOut)
{
    errOut.clear();
    unsigned short port = ChatPort();
    if (port == 0)
    {
        errOut = "the chat is not enabled (-chat)";
        return false;
    }
    if (!ChatUnlocked())
    {
        errOut = "unlock the chat first";
        return false;
    }

    CRITICAL_BLOCK(cs_chat)
    {
        if (g_fServiceStarted)
            return true;
        g_fServiceStarted = true;
    }

    if (!ChatListen(port, g_listener, errOut))
    {
        CRITICAL_BLOCK(cs_chat)
        {
            g_fServiceStarted = false;
            g_status = "could not listen: " + errOut;
        }
        return false;
    }

    if (_beginthread(ThreadChatListener, 0, NULL) == -1)
    {
        closesocket(g_listener);
        g_listener = INVALID_SOCKET;
        CRITICAL_BLOCK(cs_chat)
        {
            g_fServiceStarted = false;
            g_status = "could not start the listener thread";
        }
        errOut = "could not start the chat listener thread";
        return false;
    }
    if (_beginthread(ThreadChatPublish, 0, NULL) == -1)
        printf("btfchat: could not start the descriptor publisher\n");
    if (_beginthread(ThreadChatMailbox, 0, NULL) == -1)
        printf("btfchat: could not start the mailbox thread\n");
    if (_beginthread(ThreadChatSwaps, 0, NULL) == -1)
        printf("btfchat: could not start the swap thread\n");

    CRITICAL_BLOCK(cs_chat)
    {
        g_fListening = true;
        g_status = strprintf("listening on 127.0.0.1:%u", (unsigned)port);
    }
    printf("btfchat: listening on 127.0.0.1:%u\n", (unsigned)port);
    return true;
}

void ChatServiceStop()
{
    btf_socket_t s = INVALID_SOCKET;
    CRITICAL_BLOCK(cs_chat)
    {
        s = g_listener;
        g_listener = INVALID_SOCKET;
        g_fServiceStarted = false;
        g_status = "off";
    }
    // Closing the listener is what wakes the accept() up.
    if (s != INVALID_SOCKET)
        closesocket(s);
}

} // namespace btfchat
