// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// btfchat over a socket -- the only part of the chat that touches the network.
//
// Everything in btfchatlink is written against an abstract Stream, which is what
// lets the protocol be tested over an in-memory pipe. This is the other
// implementation of that Stream: one real socket, with a deadline. It is
// deliberately thin. Anything that needed thinking about belongs upstairs where
// it can be tested.
//
// OUTBOUND GOES THROUGH TOR, ALWAYS. ChatDialOnion refuses an address that is
// not an onion and refuses to dial with no Tor proxy configured. There is no
// clearnet fallback and there must not be: a fallback that works when Tor is
// down is a fallback that leaks the user's address precisely when the network is
// being interfered with, which is the moment it matters most.

#ifndef BITFLASH_BTFCHATSOCK_H
#define BITFLASH_BTFCHATSOCK_H

#include "btfchatlink.h"
#include "btfsock.h"

#include <string>

namespace btfchat
{

// How long one read or write may take before the link is given up on. Tor adds
// seconds of latency on a good day, so this is generous by LAN standards and
// still finite.
static const int CHAT_IO_TIMEOUT_SECS = 60;

// A Stream over one connected socket. Does not own the socket: the caller
// closes it, because the caller is what knows when the conversation is over.
//
// Read and Write are all-or-nothing, which is what the Link needs: a partial
// read leaves the channel counter out of step and the only honest answer is to
// drop the connection. Both loop over short reads and writes -- a socket is
// under no obligation to move the whole buffer at once, and treating a short
// read as an error would drop perfectly good conversations under load.
class SocketStream : public Stream
{
public:
    SocketStream(btf_socket_t s, int nTimeoutSecs = CHAT_IO_TIMEOUT_SECS)
        : sock(s), nTimeout(nTimeoutSecs) {}

    bool Write(const unsigned char* p, size_t n);
    bool Read(unsigned char* p, size_t n);

private:
    btf_socket_t sock;
    int          nTimeout;
};

// Dial "host.onion:port" through the configured Tor SOCKS5 proxy. Refuses
// anything that is not an onion address, and refuses to try at all when no Tor
// proxy is set -- see the note at the top about why there is no fallback.
bool ChatDialOnion(const std::string& endpoint, int nTimeoutSecs,
                   btf_socket_t& sockOut, std::string& errOut);

// Bind a chat listener on 127.0.0.1 at `port`. Localhost only: what reaches the
// outside is Tor forwarding its hidden service to this port, so binding any
// other interface would expose the chat on the clearnet by accident.
bool ChatListen(unsigned short port, btf_socket_t& sockOut, std::string& errOut);

} // namespace btfchat

#endif
