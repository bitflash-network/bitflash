// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "headers.h"
#include "btfchatsock.h"
#include "proxy.h"

#include <string.h>

namespace btfchat
{

// One select() on a single socket, so a dead peer costs a timeout instead of a
// thread. Returns 1 ready, 0 timed out, -1 error.
static int WaitOne(btf_socket_t s, bool fWrite, int nSecs)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    struct timeval tv;
    tv.tv_sec  = nSecs > 0 ? nSecs : 0;
    tv.tv_usec = 0;
#ifdef _WIN32
    int n = select(0, fWrite ? NULL : &fds, fWrite ? &fds : NULL, NULL, &tv);
#else
    int n = select((int)s + 1, fWrite ? NULL : &fds, fWrite ? &fds : NULL, NULL, &tv);
#endif
    if (n < 0)
        return -1;
    return n == 0 ? 0 : 1;
}

bool SocketStream::Write(const unsigned char* p, size_t n)
{
    if (sock == INVALID_SOCKET || (!p && n))
        return false;
    size_t nSent = 0;
    int64 nDeadline = GetTime() + nTimeout;
    while (nSent < n)
    {
        if (fShutdown)
            return false;
        if (GetTime() > nDeadline)
            return false;
        int nReady = WaitOne(sock, true, 1);
        if (nReady < 0)
            return false;
        if (nReady == 0)
            continue;   // still within the deadline, keep waiting
        int r = send(sock, (const char*)(p + nSent), (int)(n - nSent), BTF_SEND_FLAGS);
        if (r > 0)
        {
            nSent += (size_t)r;
            continue;
        }
        if (r == 0)
            return false;
#ifdef _WIN32
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK || e == WSAEINTR)
            continue;
#else
        if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
            continue;
#endif
        return false;
    }
    return true;
}

bool SocketStream::Read(unsigned char* p, size_t n)
{
    if (sock == INVALID_SOCKET || (!p && n))
        return false;
    size_t nGot = 0;
    int64 nDeadline = GetTime() + nTimeout;
    while (nGot < n)
    {
        if (fShutdown)
            return false;
        if (GetTime() > nDeadline)
            return false;
        int nReady = WaitOne(sock, false, 1);
        if (nReady < 0)
            return false;
        if (nReady == 0)
            continue;
        int r = recv(sock, (char*)(p + nGot), (int)(n - nGot), 0);
        if (r > 0)
        {
            nGot += (size_t)r;
            continue;
        }
        if (r == 0)
            return false;   // the peer closed; a short frame is not a frame
#ifdef _WIN32
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK || e == WSAEINTR)
            continue;
#else
        if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
            continue;
#endif
        return false;
    }
    return true;
}

bool ChatDialOnion(const std::string& endpoint, int nTimeoutSecs,
                   btf_socket_t& sockOut, std::string& errOut)
{
    sockOut = INVALID_SOCKET;
    errOut.clear();

    size_t nColon = endpoint.rfind(':');
    if (nColon == std::string::npos || nColon + 1 >= endpoint.size())
    {
        errOut = "the endpoint needs a host and a port";
        return false;
    }
    std::string host = endpoint.substr(0, nColon);
    std::string strPort = endpoint.substr(nColon + 1);
    for (size_t i = 0; i < strPort.size(); i++)
        if (strPort[i] < '0' || strPort[i] > '9')
        {
            errOut = "the port is not a number";
            return false;
        }
    long nPort = atol(strPort.c_str());
    if (nPort <= 0 || nPort > 65535)
    {
        errOut = "the port is out of range";
        return false;
    }

    // Onion only, and no fallback. A chat that reaches a clearnet address the
    // moment Tor is unavailable hands over the user's IP exactly when somebody
    // is interfering with the network.
    if (!BtfIsTorOnionHost(host))
    {
        errOut = "a chat endpoint has to be an onion address";
        return false;
    }
    if (!BtfTorProxyEnabled())
    {
        errOut = "no Tor proxy is configured, and there is no other way out";
        return false;
    }

    SOCKET s = BtfConnectSocket(host, (unsigned short)nPort, 0, nTimeoutSecs);
    if (s == INVALID_SOCKET)
    {
        errOut = "could not reach " + endpoint + " over Tor";
        return false;
    }
    sockOut = s;
    return true;
}

bool ChatListen(unsigned short port, btf_socket_t& sockOut, std::string& errOut)
{
    sockOut = INVALID_SOCKET;
    errOut.clear();
    if (port == 0)
    {
        errOut = "no chat port";
        return false;
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        errOut = "could not create the chat listener socket";
        return false;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    // Loopback only. Tor forwards its hidden service here; binding anything
    // wider would publish the chat on the clearnet without anyone asking for it.
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(s, 8) != 0)
    {
        closesocket(s);
        errOut = strprintf("could not listen on 127.0.0.1:%u for the chat", (unsigned)port);
        return false;
    }

    sockOut = s;
    return true;
}

} // namespace btfchat
