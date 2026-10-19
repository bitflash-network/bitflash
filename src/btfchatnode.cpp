// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "btfchatnode.h"
#include "btfchatsock.h"
#include "btfchatbox.h"
#include "btfaddr.h"
#include "nostr.h"
#include "tor.h"

#include <sodium.h>
#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>

#include <algorithm>

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

    // The two halves are stored as one object so a single seal covers both.
    std::string err;
    size_t nSplit = plain.find('\n');
    if (nSplit == std::string::npos)
        return false;
    std::string strRoster = plain.substr(0, nSplit);
    std::string strHistory = plain.substr(nSplit + 1);
    if (!g_roster.FromJson(strRoster, err))
        printf("btfchat: the roster in the store did not load: %s\n", err.c_str());
    if (!strHistory.empty() && !g_history.FromJson(strHistory, err))
        printf("btfchat: the history in the store did not load: %s\n", err.c_str());
    return true;
}

static bool SaveStore()
{
    if (!g_fUnlocked)
        return false;
    // One line of roster, then the history: newline-separated because neither
    // half's JSON contains a raw newline, and it keeps the seal to one blob.
    std::string plain = g_roster.ToJson() + "\n" + g_history.ToJson();
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

    std::string meeting, onion;
    unsigned char encPub[32];
    if (!BtfResolve(peerAddr, meeting, encPub, &onion) || onion.empty())
    {
        // Either nothing is published for that address or it has no onion. From
        // here the two are the same thing: no way to reach them right now.
        errOut = "could not find that address on the discovery relays";
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
    std::string meeting, onion;
    if (!BtfResolve(peerAddr, meeting, out, &onion))
    {
        errOut = "could not find that address on the discovery relays";
        return false;
    }
    return true;
}

static bool LeaveInMailbox(const std::string& peerAddr, const Identity& id,
                           const std::string& frameJson, std::string& errOut)
{
    errOut.clear();

    std::string ann;
    if (!BtfQueryChatEpochKeys(peerAddr, ann, errOut))
        return false;

    int64_t nEpoch = 0;
    unsigned char their_x[btf::CHAN_KEYBYTES];
    unsigned char their_kem[btf::CHAN_KEM_PUBBYTES];
    // Verified against the address we asked for, not the one the answer claims:
    // otherwise a relay hands back somebody else's valid announcement and the
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
    return BtfPostChatEnvelope(tag, env, errOut);
}

bool ChatSendText(const std::string& peerAddr, const std::string& text,
                  bool& fLeftInMailboxOut, std::string& errOut)
{
    fLeftInMailboxOut = false;
    errOut.clear();
    if (!ChatUnlocked()) { errOut = "the chat is locked"; return false; }
    if (text.empty()) { errOut = "nothing to send"; return false; }
    if (text.size() > MAX_TEXT_BYTES) { errOut = "that message is too long"; return false; }

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

    Frame f;
    f.kind = MSG_TEXT;
    f.sent = GetTime();
    f.text = text;
    std::string js;
    if (!SignFrame(g_secp, id, f, js, errOut))
    {
        IdentityClear(id);
        return false;
    }
    bool fOk = SendOneFrame(peerAddr, js, errOut);
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
            errOut = "could not connect (" + strLive + ") and could not leave a message (" + strBox + ")";
    }
    IdentityClear(id);

    // Only recorded once it is actually gone. A line in the history that never
    // left is a lie the user acts on.
    if (fOk)
        CRITICAL_BLOCK(cs_chat)
        {
            std::string e;
            g_history.Append(f, peerAddr, true, e);
            SaveStore();
        }
    return fOk;
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
                printf("btfchat: delivered a frame from %s\n", f.from.c_str());

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

// Publishes the chat's descriptor on the discovery relays and keeps it fresh.
// Separate from the node's own publisher, and signed by the chat key, so nothing
// on a relay ties the two identities together.
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

    for (size_t i = 0; i < contacts.size() && !fShutdown; i++)
    {
        // This epoch and the previous one: a message left at 23:59 is collected
        // at 00:01, and MAILBOX_KEEP_EPOCHS is what makes both openable.
        // Resolved once per contact, not once per epoch: it is a relay round
        // trip over Tor, and the answer is the same both times through.
        unsigned char their_pub[btf::CHAN_KEYBYTES];
        std::string errResolve;
        if (!ResolvePeerStaticChanKey(contacts[i], their_pub, errResolve))
            continue;

        for (int back = 0; back < (int)MAILBOX_KEEP_EPOCHS; back++)
        {
            std::string tag, err;
            if (!MailboxTag(id.chan_sk, their_pub, nEpochNow - back, tag))
                break;

            int64_t nSince = 0;
            CRITICAL_BLOCK(cs_chat)
            {
                std::map<std::string, int64_t>::const_iterator it = g_mapPolledUntil.find(tag);
                if (it != g_mapPolledUntil.end())
                    nSince = it->second;
            }

            std::vector<std::vector<unsigned char> > envs;
            if (!BtfFetchChatEnvelopes(tag, nSince, envs, err))
                continue;

            for (size_t k = 0; k < envs.size(); k++)
            {
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

            CRITICAL_BLOCK(cs_chat)
                g_mapPolledUntil[tag] = nNow;
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

                EpochKeys pub;
                Identity id;
                bool fHave = false;
                CRITICAL_BLOCK(cs_chat)
                    if (g_fUnlocked)
                    {
                        pub.epoch = MailboxEpoch(GetTime());
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
                        if (!BtfPublishChatEpochKeys(id.sign_sk, ann, err))
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
            }

            // Two minutes. Polling harder buys latency for somebody who is
            // offline anyway, and every poll is a Tor circuit to a relay --
            // which is traffic a watcher can count.
            for (int i = 0; i < 120 && !fShutdown; i++)
                Sleep(1000);
        }
    }
    catch (std::exception& e) { PrintException(&e, "ThreadChatMailbox()"); }
    catch (...)               { PrintException(NULL, "ThreadChatMailbox()"); }
}

static void ThreadChatPublish(void* parg)
{
    IMPLEMENT_RANDOMIZE_STACK(ThreadChatPublish(parg));
    try
    {
        bool fEverPublished = false;
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

                    if (BtfPublishChatDescriptor(sk, hex, onion, err))
                    {
                        fEverPublished = true;
                        CRITICAL_BLOCK(cs_chat)
                            g_status = "reachable at " + onion;
                    }
                    else
                    {
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

            // Twenty minutes once it is out there -- the descriptor is a
            // replaceable event and relays forget. Ten seconds until then: on a
            // fresh start the chat's onion service does not exist yet, and
            // waiting twenty minutes to discover that it now does would leave the
            // user sitting in front of a chat nobody can reach, with nothing on
            // screen explaining the wait.
            int nWait = fEverPublished ? 20 * 60 : 10;
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
