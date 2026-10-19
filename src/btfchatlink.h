// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// btfchat link -- the conversation on the wire, and the one safe order to take
// an incoming frame apart.
//
// The pieces below this were all testable without a network because none of them
// touched one. This one has to, so the bytes go through an abstract Stream: the
// protocol is exercised over an in-memory pipe in the tests and over a Tor
// socket in the program, and it is the same code either way. Nothing here calls
// connect(), and nothing here knows what an onion address is.
//
// THE ORDER MATTERS AND IT IS NOT OBVIOUS. An incoming frame has to pass, in
// exactly this sequence:
//
//   1. the channel      -- btfchan opens it; a bad tag or a skipped counter and
//                          there is nothing to look at
//   2. the signature    -- OpenFrame, under the key the sender's .btf decodes to
//   3. consent          -- the roster gate, which is where a stranger stops
//   4. replay           -- only now, so a stranger cannot fill the table
//   5. the state change -- roster event or history line, never both
//
// Every one of those steps is refusable and the earlier ones are cheaper, which
// is the other reason for the order. Getting it wrong is not a crash, it is a
// quiet downgrade: check replay before consent and a flood of fake identities
// fills the table; check consent before the signature and anyone can spend our
// roster lookups; skip the signature entirely and the relay writes the messages.
//
// So the order lives in ONE function, Inbox::Deliver, and callers do not get to
// assemble it themselves.

#ifndef BITFLASH_BTFCHATLINK_H
#define BITFLASH_BTFCHATLINK_H

#include "btfchan.h"
#include "btfchat.h"
#include "btfchatlog.h"
#include "btfchatmsg.h"

#include <cstring>
#include <string>
#include <vector>
#include <stddef.h>
#include <stdint.h>

namespace btfchat
{

// Biggest frame body accepted off a link: the JSON ceiling plus what the channel
// adds. The length word comes from a stranger, so it is checked against this
// before a single byte is allocated.
static const size_t MAX_LINK_BODY = MAX_FRAME_BYTES + 64;

// A byte stream that reads and writes exactly what it is asked for, or fails.
// Partial success is not a state this protocol can recover from: half a frame
// read means the channel counter is out of step, and the honest answer is to
// drop the connection.
class Stream
{
public:
    virtual ~Stream() {}
    virtual bool Write(const unsigned char* p, size_t n) = 0;
    virtual bool Read(unsigned char* p, size_t n) = 0;
};

// One live conversation. Holds session keys: Close() zeroes them, and the
// destructor calls Close().
class Link
{
public:
    Link() : fOpen(false) { memset(&sess, 0, sizeof(sess)); }
    ~Link() { Close(); }

    // Dial. `peer_chan_pub` is the X25519 key the peer's verified descriptor
    // named. A caller that passes a key from anywhere else -- a relay's answer
    // that was not checked, a field off the wire -- has encryption and no
    // authentication, which is the shape of a man in the middle.
    bool ConnectAsClient(Stream& s, const unsigned char peer_chan_pub[btf::CHAN_KEYBYTES],
                         std::string& errOut);

    // Accept. Our static secret authenticates us to whoever dialled: they
    // checked it against the address they looked up.
    bool AcceptAsEndpoint(Stream& s, const unsigned char my_chan_sk[btf::CHAN_KEYBYTES],
                          std::string& errOut);

    bool SendFrame(Stream& s, const std::string& frameJson, std::string& errOut);

    // Read one frame. Fails on a length that breaks MAX_LINK_BODY, a short read,
    // or a body the channel refuses. After a failure the link is closed: a
    // stream whose framing slipped cannot be resynchronized.
    bool RecvFrame(Stream& s, std::string& frameJsonOut, std::string& errOut);

    void Close();
    bool IsOpen() const { return fOpen; }

private:
    btf::ChanSession sess;
    bool             fOpen;
};

// Everything one identity needs to act on an incoming frame. The pointers are
// borrowed, not owned, and all four are required.
struct Inbox
{
    void*        secpctx;   // secp256k1_context*
    std::string  myAddress;
    Roster*      roster;
    ReplayGuard* replay;
    History*     history;

    Inbox() : secpctx(NULL), roster(NULL), replay(NULL), history(NULL) {}

    // The whole inbound path, in the order the header describes. Returns true
    // when the frame was accepted AND its effect applied -- an invite recorded,
    // a message filed, a group joined as pending. `out` is filled whenever the
    // frame itself was valid, so a caller can log what it refused.
    //
    // `peer` is the address on the other end of the link. For a direct frame it
    // has to match the frame's sender: the link says who we are talking to, the
    // signature says who wrote it, and if those disagree the frame is being
    // forwarded by somebody. Inside a group that is normal; one to one it is not.
    bool Deliver(const std::string& frameJson, const std::string& peer, int64_t nNow,
                 Frame& out, std::string& errOut);
};

} // namespace btfchat

#endif
