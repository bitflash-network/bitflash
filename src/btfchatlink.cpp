// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.

#include "btfchatlink.h"

#include <sodium.h>

#include <cstring>

namespace btfchat
{

// ---- the link --------------------------------------------------------------

void Link::Close()
{
    btf::ChanSessionClear(sess);
    fOpen = false;
}

bool Link::ConnectAsClient(Stream& s, const unsigned char peer_chan_pub[btf::CHAN_KEYBYTES],
                           std::string& errOut)
{
    errOut.clear();
    Close();
    if (!btf::ChanInit()) { errOut = "libsodium failed to initialize"; return false; }

    btf::ChanClientCtx ctx;
    unsigned char hs1[btf::CHAN_HS1BYTES];
    if (!btf::ChanClientFlight1(ctx, hs1))
    {
        btf::ChanClientCtxClear(ctx);
        errOut = "flight 1 failed";
        return false;
    }
    if (!s.Write(hs1, sizeof(hs1)))
    {
        btf::ChanClientCtxClear(ctx);
        errOut = "could not send flight 1";
        return false;
    }

    std::vector<unsigned char> hs2(btf::CHAN_HS2BYTES);
    if (!s.Read(&hs2[0], hs2.size()))
    {
        btf::ChanClientCtxClear(ctx);
        errOut = "no flight 2 from the other side";
        return false;
    }

    std::vector<unsigned char> hs3(btf::CHAN_HS3BYTES);
    bool fOk = btf::ChanClientFlight3(ctx, peer_chan_pub, &hs2[0], &hs3[0], sess);
    btf::ChanClientCtxClear(ctx);
    if (!fOk)
    {
        btf::ChanSessionClear(sess);
        errOut = "flight 3 failed -- wrong endpoint key?";
        return false;
    }
    if (!s.Write(&hs3[0], hs3.size()))
    {
        btf::ChanSessionClear(sess);
        errOut = "could not send flight 3";
        return false;
    }

    fOpen = true;
    return true;
}

bool Link::AcceptAsEndpoint(Stream& s, const unsigned char my_chan_sk[btf::CHAN_KEYBYTES],
                            std::string& errOut)
{
    errOut.clear();
    Close();
    if (!btf::ChanInit()) { errOut = "libsodium failed to initialize"; return false; }

    unsigned char hs1[btf::CHAN_HS1BYTES];
    if (!s.Read(hs1, sizeof(hs1))) { errOut = "no flight 1"; return false; }

    btf::ChanEndpointCtx ctx;
    std::vector<unsigned char> hs2(btf::CHAN_HS2BYTES);
    if (!btf::ChanEndpointFlight2(ctx, hs1, &hs2[0]))
    {
        btf::ChanEndpointCtxClear(ctx);
        errOut = "flight 2 failed";
        return false;
    }
    if (!s.Write(&hs2[0], hs2.size()))
    {
        btf::ChanEndpointCtxClear(ctx);
        errOut = "could not send flight 2";
        return false;
    }

    std::vector<unsigned char> hs3(btf::CHAN_HS3BYTES);
    if (!s.Read(&hs3[0], hs3.size()))
    {
        btf::ChanEndpointCtxClear(ctx);
        errOut = "no flight 3";
        return false;
    }

    bool fOk = btf::ChanEndpointFinish(ctx, my_chan_sk, &hs3[0], sess);
    btf::ChanEndpointCtxClear(ctx);
    if (!fOk)
    {
        btf::ChanSessionClear(sess);
        errOut = "the handshake did not complete";
        return false;
    }

    fOpen = true;
    return true;
}

bool Link::SendFrame(Stream& s, const std::string& frameJson, std::string& errOut)
{
    errOut.clear();
    if (!fOpen) { errOut = "the link is not open"; return false; }
    if (frameJson.empty()) { errOut = "nothing to send"; return false; }
    if (frameJson.size() > MAX_FRAME_BYTES)
    {
        // Refuse to put on the wire what the other side is required to refuse.
        errOut = "the frame is bigger than the wire limit";
        return false;
    }

    std::vector<unsigned char> wire =
        btf::ChanEncryptFrame(sess, (const unsigned char*)frameJson.data(), frameJson.size());
    if (wire.size() < 4)
    {
        Close();
        errOut = "sealing the frame failed";
        return false;
    }
    if (!s.Write(&wire[0], wire.size()))
    {
        // The counter has already advanced, so this link cannot be reused: the
        // other side would see a gap and refuse everything after it.
        Close();
        errOut = "the write failed";
        return false;
    }
    return true;
}

bool Link::RecvFrame(Stream& s, std::string& frameJsonOut, std::string& errOut)
{
    errOut.clear();
    frameJsonOut.clear();
    if (!fOpen) { errOut = "the link is not open"; return false; }

    unsigned char len[4];
    if (!s.Read(len, sizeof(len)))
    {
        Close();
        errOut = "the link closed";
        return false;
    }
    size_t n = ((size_t)len[0] << 24) | ((size_t)len[1] << 16) |
               ((size_t)len[2] << 8)  |  (size_t)len[3];

    // A length from a stranger, checked before anything is allocated for it.
    if (n < (size_t)(btf::CHAN_CTRBYTES + btf::CHAN_MACBYTES) || n > MAX_LINK_BODY)
    {
        Close();
        errOut = "the frame length is impossible";
        return false;
    }

    std::vector<unsigned char> body(n);
    if (!s.Read(&body[0], n))
    {
        Close();
        errOut = "the frame was cut short";
        return false;
    }

    std::vector<unsigned char> pt;
    if (!btf::ChanDecryptBody(sess, &body[0], n, pt))
    {
        // A forgery, a replay inside this connection, or a reorder. None of the
        // three leaves a stream we can keep reading.
        Close();
        errOut = "the frame did not authenticate";
        return false;
    }

    frameJsonOut.assign((const char*)(pt.empty() ? (const unsigned char*)"" : &pt[0]), pt.size());
    if (!pt.empty())
        sodium_memzero(&pt[0], pt.size());
    return true;
}

// ---- the one safe order ----------------------------------------------------

bool Inbox::Deliver(const std::string& frameJson, const std::string& peer, int64_t nNow,
                    Frame& out, std::string& errOut)
{
    errOut.clear();
    if (!secpctx || !roster || !replay || !history || myAddress.empty())
    {
        errOut = "the inbox is not wired up";
        return false;
    }

    // 2. The signature. Under the key the sender's own address decodes to, so
    //    nothing downstream has to wonder whether the sender is real.
    Frame f;
    if (!OpenFrame(secpctx, frameJson, f, errOut))
        return false;
    out = f;

    // The link says who we are talking to; the signature says who wrote it. One
    // to one those must agree, or the frame is being relayed by a third party
    // who should not be in the middle of a direct conversation.
    if (!peer.empty() && f.kind != MSG_GROUP_TEXT && f.kind != MSG_GROUP_INVITE &&
        f.from != peer)
    {
        errOut = "the frame was written by someone other than the peer we are talking to";
        return false;
    }

    // 3. Consent. Group frames are judged against their group, everything else
    //    against the sender.
    if (f.kind == MSG_GROUP_TEXT)
    {
        if (!roster->MayDeliverGroup(f.group, f.from, errOut))
            return false;
    }
    else
    {
        if (!roster->MayDeliver(f.from, f.kind, errOut))
            return false;
    }

    // A group invite has one more thing to prove before it counts: that the
    // admin it names actually issued it, for us. Checked here, before the frame
    // is allowed to consume a replay slot or touch the roster.
    if (f.kind == MSG_GROUP_INVITE)
    {
        if (!VerifyGroupInvite(secpctx, f.from, f.group, f.text, myAddress, f.proof, errOut))
            return false;
    }

    // 4. Replay. After consent, so only frames we were willing to receive can
    //    take room in the table.
    if (!replay->Accept(f, nNow, errOut))
        return false;

    // 5. The effect. Exactly one of these per frame.
    switch (f.kind)
    {
    case MSG_INVITE:
        return roster->NoteIncomingInvite(f.from, f.text, f.sent, errOut);

    case MSG_INVITE_ACCEPT:
        return roster->NoteInviteAccepted(f.from, errOut);

    case MSG_GROUP_INVITE:
        return roster->NoteGroupInvite(f.group, f.text, f.from, f.from, f.sent, errOut);

    case MSG_TEXT:
        return history->Append(f, f.from, false, errOut);

    case MSG_GROUP_TEXT:
        return history->Append(f, std::string(), false, errOut);
    }

    // Unreachable: OpenFrame refuses a kind this build does not know. Here for
    // the day someone adds a kind and forgets this switch -- it fails closed.
    errOut = "no handler for that frame kind";
    return false;
}

} // namespace btfchat
