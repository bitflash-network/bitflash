// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// See rpcclient.h.

#include "headers.h"
#include "rpcclient.h"

#include <cstdio>

using json = nlohmann::json;

bool ReadRpcCookie(const std::string& path, std::string& authOut, std::string& errOut)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f)
    {
        errOut = "no cookie at " + path;
        return false;
    }
    char buf[512];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = 0;
    authOut = buf;
    while (!authOut.empty() && (authOut[authOut.size() - 1] == '\n' || authOut[authOut.size() - 1] == '\r'))
        authOut.erase(authOut.size() - 1);
    if (authOut.find(':') == std::string::npos)
    {
        errOut = path + " is malformed";
        return false;
    }
    return true;
}

static std::string Base64(const std::string& in)
{
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, bits = -6;
    for (size_t i = 0; i < in.size(); i++)
    {
        val = (val << 8) + (unsigned char)in[i];
        bits += 8;
        while (bits >= 0)
        {
            out.push_back(t[(val >> bits) & 0x3F]);
            bits -= 6;
        }
    }
    if (bits > -6)
        out.push_back(t[((val << 8) >> (bits + 8)) & 0x3F]);
    while (out.size() % 4)
        out.push_back('=');
    return out;
}

bool LoopbackRpcCall(const LoopbackRpc& to, const std::string& method, const json& params,
                     json& resultOut, std::string& errOut, int* pnCodeOut)
{
    if (pnCodeOut)
        *pnCodeOut = 0;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
    {
        errOut = "could not open a socket";
        return false;
    }
#ifdef _WIN32
    DWORD tv = to.nTimeoutSecs * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = to.nTimeoutSecs;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#endif
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((unsigned short)to.nPort);
    if (connect(s, (struct sockaddr*)&a, sizeof(a)) != 0)
    {
        closesocket(s);
        errOut = strprintf("%s is not answering on 127.0.0.1:%d", to.strWho.c_str(), to.nPort);
        return false;
    }

    json req;
    req["jsonrpc"] = "1.0";
    req["id"] = 1;
    req["method"] = method;
    req["params"] = params;
    std::string body = req.dump();
    std::string http = "POST " + to.strPath + " HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic " +
                       Base64(to.strAuth) + "\r\nContent-Type: application/json\r\nContent-Length: " +
                       strprintf("%u", (unsigned)body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    size_t sent = 0;
    while (sent < http.size())
    {
        int n = send(s, http.data() + sent, (int)(http.size() - sent), 0);
        if (n <= 0)
        {
            closesocket(s);
            errOut = to.strWho + " closed the connection";
            return false;
        }
        sent += n;
    }

    std::string resp;
    std::vector<char> buf(65536);
    bool fTooBig = false;
    for (;;)
    {
        int n = recv(s, &buf[0], (int)buf.size(), 0);
        if (n <= 0)
            break;
        resp.append(&buf[0], n);
        if (resp.size() > to.nMaxBytes)
        {
            fTooBig = true;
            break;
        }
    }
    closesocket(s);
    if (fTooBig)
    {
        errOut = to.strWho + " sent more than this call expects";
        return false;
    }

    size_t p = resp.find("\r\n\r\n");
    if (p == std::string::npos)
    {
        errOut = to.strWho + " sent no answer";
        return false;
    }
    if (resp.compare(0, 12, "HTTP/1.1 401") == 0 || resp.compare(0, 12, "HTTP/1.0 401") == 0)
    {
        errOut = to.strWho + " refused the cookie or password (was it restarted? a cookie changes every start)";
        return false;
    }
    json j;
    try { j = json::parse(resp.substr(p + 4)); }
    catch (...)
    {
        // Bitcoin Core answers an unknown /wallet/<name> with a plain 404 page.
        errOut = resp.compare(0, 12, "HTTP/1.1 404") == 0 ? to.strWho + " has no such wallet or path"
                                                          : to.strWho + "'s answer is not JSON";
        return false;
    }
    if (j.contains("error") && !j["error"].is_null())
    {
        errOut = j["error"].is_object() && j["error"].contains("message") && j["error"]["message"].is_string()
                     ? j["error"]["message"].get<std::string>() : j["error"].dump();
        if (pnCodeOut && j["error"].is_object() && j["error"].contains("code") && j["error"]["code"].is_number_integer())
            *pnCodeOut = j["error"]["code"].get<int>();
        return false;
    }
    resultOut = j.contains("result") ? j["result"] : json(nullptr);
    return true;
}
