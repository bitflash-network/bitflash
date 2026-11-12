// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// For the fuzz harnesses that play the other end of a connection: Tor's
// control port, a SOCKS5 proxy, an RPC caller, a relay or a server the node
// asked something. The input is written into one end of a socketpair, which
// is then shut for writing, and the node's own socket code reads the other
// end: it sees exactly those bytes, then the end of the stream, as from a
// peer that sent them and hung up. What the node writes back stays queued on
// the harness's end, unread.
//
// Linux only, like every harness here. Inputs are capped well below what a
// socket buffer holds, so writing them never blocks.

#ifndef BITFLASH_FUZZ_SOCKET_H
#define BITFLASH_FUZZ_SOCKET_H

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static const size_t FUZZ_SOCKET_MAX_INPUT = 64 * 1024;

class CFuzzSocketPair
{
public:
    int fdNode;   // the node's end: hand this to the code under test
    int fdPeer;   // the harness's end

    CFuzzSocketPair(const uint8_t* data, size_t size) : fdNode(-1), fdPeer(-1)
    {
        // A node write to a peer that is gone must be an error, not a signal.
        signal(SIGPIPE, SIG_IGN);
        int fd[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) != 0)
        {
            perror("fuzz: socketpair");
            abort();
        }
        fdNode = fd[0];
        fdPeer = fd[1];
        int nBuf = 4 * (int)FUZZ_SOCKET_MAX_INPUT;
        setsockopt(fdPeer, SOL_SOCKET, SO_SNDBUF, &nBuf, sizeof(nBuf));
        setsockopt(fdNode, SOL_SOCKET, SO_RCVBUF, &nBuf, sizeof(nBuf));
        size_t off = 0;
        while (off < size)
        {
            ssize_t n = send(fdPeer, data + off, size - off, MSG_NOSIGNAL | MSG_DONTWAIT);
            if (n <= 0)
            {
                fprintf(stderr, "fuzz: socketpair took only %zu of %zu bytes\n", off, size);
                abort();
            }
            off += (size_t)n;
        }
        shutdown(fdPeer, SHUT_WR);
    }

    ~CFuzzSocketPair()
    {
        if (fdNode >= 0)
            close(fdNode);
        if (fdPeer >= 0)
            close(fdPeer);
    }

private:
    CFuzzSocketPair(const CFuzzSocketPair&);
    CFuzzSocketPair& operator=(const CFuzzSocketPair&);
};

#endif
