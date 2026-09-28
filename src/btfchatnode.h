// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// btfchat inside the node -- where the chat identity comes from, and the service
// that carries it.
//
// WHY THE PHRASE NEVER APPEARS. The chat identity grows from the same twelve
// words as the wallet, but nothing here ever sees them. The wallet does not keep
// the BIP39 seed; it keeps the BIP32 master key and chain code that were derived
// from it, and those two are a deterministic function of that seed. Feeding them
// to the chat gives the same identity for the same phrase, on any machine, with
// the phrase itself never reaching this code, this screen, or this process's
// memory after restore. A recovery phrase that is not in memory cannot be
// screenshotted, logged or swapped out.
//
// Two consequences worth knowing:
//   * an encrypted wallet has to be unlocked first -- the master key is
//     encrypted at rest, which is the point of encrypting it
//   * a wallet restored WITH a BIP39 passphrase has a different master key, so
//     it has a different chat identity. Correct, and worth saying out loud: the
//     25th word makes a different wallet, and a different wallet is a different
//     person as far as the chat is concerned.
//
// THE SERVICE. One thread accepts on 127.0.0.1:<chat port>, which is where Tor
// forwards the chat's own hidden service, and one short-lived thread serves each
// connection. Outbound is a connection per message: resolve the peer's address
// on the discovery relays, dial its onion through Tor, hand over one frame,
// close. No pooling yet -- it costs a Tor circuit per message, and a pool is an
// optimisation that can wait until the thing is proven to work at all.
//
// THE OFFLINE PATH. When a dial fails -- and for somebody who is not online it
// always will -- the message is sealed to that person's published epoch keys and
// left under the tag the two of them share, which rotates daily. A poll thread
// collects what was left for us. The relay sees random tag names appearing and
// disappearing, posts signed by one-time keys, and nothing it can map to a
// person. What it does see is that a tag was written to, when, and how big: that
// is the price of not needing both people online at once, and no amount of
// cryptography removes it. See btfchatbox.h for the full accounting.

#ifndef BITFLASH_BTFCHATNODE_H
#define BITFLASH_BTFCHATNODE_H

#include "btfchat.h"
#include "btfchatlog.h"
#include "btfchatmsg.h"

#include <string>
#include <vector>

namespace btfchat
{

// The 64 bytes the chat identity is derived from: the wallet's BIP32 master key
// followed by its chain code. False when the wallet has no HD seed installed
// (a pre-phrase wallet) or is locked.
bool ChatSeedFromWallet(std::vector<unsigned char>& out, std::string& errOut);

// Derive this wallet's chat identity for a session password. Just the two steps
// above joined up, kept in one place so no caller invents its own order.
bool UnlockIdentity(const std::string& password, Identity& out, std::string& errOut);

// ---- the session -----------------------------------------------------------
//
// One unlocked identity with its roster, its history and its replay table. Held
// behind a lock because the listener threads and the interface both reach it.
// Locking wipes the key material; the roster and history stay on disk, sealed.

// Unlock with the session password. A wrong password does not fail -- it opens a
// different, empty identity -- so the caller must show the address it landed on
// and let the person recognise it. That is not a wart, it is what makes the
// password impossible to verify offline by anybody, us included.
bool ChatUnlock(const std::string& password, std::string& errOut);

// Wipe the identity and every session key from memory. The service keeps
// running; it simply has nothing to answer with, and refuses connections.
void ChatLock();

bool        ChatUnlocked();
std::string ChatAddress();          // "" while locked

// The user did something. Feeds the fifteen-minute inactivity lock.
void ChatTouch();

// Called from the interface's frame loop: locks the session if it has been idle
// past the limit. Returns true if it locked on this call.
bool ChatCheckInactivity();

// Seconds before the inactivity lock trips, 0 when locked.
int64_t ChatSecondsBeforeLock();

// ---- the service -----------------------------------------------------------

// The local port the chat listens on, and the port Tor forwards its chat hidden
// service to. Set before managed Tor starts; 0 means no chat at all, and then
// the torrc gets no second onion service.
void           ChatSetPort(unsigned short port);
unsigned short ChatPort();

// Start the listener and the descriptor publisher. Safe to call repeatedly; it
// starts nothing twice. Fails while the session is locked -- there is no key to
// answer a handshake with.
bool ChatServiceStart(std::string& errOut);
void ChatServiceStop();
bool ChatServiceRunning();

// One line for the interface: what the service is doing, or why it is not.
std::string ChatServiceStatus();

// This chat identity's own onion endpoint, as published. "" until Tor makes it.
std::string ChatOnionEndpoint();

// ---- what the interface calls ----------------------------------------------
//
// Each of these is one Tor dial, so each can take seconds and none of them may
// be called from the frame loop. They return false with a reason the interface
// can show.

// Ask to talk. Records the outgoing invite locally first, so a dial that fails
// halfway does not leave us thinking we never asked.
bool ChatInvite(const std::string& peerAddr, const std::string& note, std::string& errOut);

// Accept an invite that arrived, and tell the other side.
bool ChatAcceptInvite(const std::string& peerAddr, std::string& errOut);

// Refuse an invite. Nothing is sent: somebody who does not get an answer learns
// less than somebody who gets a refusal.
bool ChatDeclineInvite(const std::string& peerAddr, std::string& errOut);

// Block, permanently and locally. Nothing is sent, for the same reason.
bool ChatBlock(const std::string& peerAddr, std::string& errOut);

// Send a message to an accepted contact. Tries the live connection first and
// falls back to the mailbox, so a message to somebody offline still arrives --
// later. `fLeftInMailboxOut` says which happened, because "sent" and "left for
// them" are different promises and the interface should not blur them.
bool ChatSendText(const std::string& peerAddr, const std::string& text,
                  bool& fLeftInMailboxOut, std::string& errOut);

// Collect and deliver whatever was left in our mailboxes. Called by the poll
// thread; exposed so the interface can offer a "check now".
int ChatPollMailboxes(std::string& errOut);

// ---- what the interface reads ----------------------------------------------

void ChatPendingInvites(std::vector<Invite>& out);
void ChatContacts(std::vector<std::string>& out);          // accepted, sorted
void ChatConversation(const std::string& peerAddr, std::vector<LogEntry>& out);
// What is still waiting to go to that address, oldest first. Kept apart from the
// conversation on purpose: these have not been delivered, and showing them as if
// they had would be the one lie this program must not tell.
bool ChatPendingFor(const std::string& peerAddr, std::vector<Pending>& out);
PeerState ChatPeerState(const std::string& peerAddr);

// Where the sealed roster and history live, so the interface can say so.
std::string ChatStorePath();

} // namespace btfchat

#endif
