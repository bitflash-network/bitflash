// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for the chat relay: what a peer or a chat app can send a node
// about chat records (chatrec, chatput, chatget, getchatinv, getchatdir, and
// the inv/getdata that announce and fetch them), through the real handlers:
// ProcessMessage() in main.cpp and ChatRelayProcessMessage() behind it, into
// the node's ChatStore.
//
// fuzz-p2p-payload reaches the same commands with raw payloads, but a record
// needs proof of work and, for descriptors and epoch keys, a signature, so
// nearly every record it builds is refused at the first check. Here the store
// takes 4 bits of work instead of 20 (ChatRelayFuzzReset, compiled only with
// -DBITFLASH_FUZZ), the harness mines and signs records from fields the input
// chooses, and the checks behind the work rule are fuzzed too: supersession of
// signed records, the per-tag ceiling, expiry, the budgets, queries, the
// rations and the "only what was announced" rule for chatrec.
//
// Input: a sequence of operations, each [op][len lo][len hi][body]:
//   op % 8 == 0  raw message: body[0] picks the command, the rest is payload
//   op % 8 == 1  an envelope record from fields, sent as chatput
//   op % 8 == 2  the same, announced with inv and then sent as chatrec
//   op % 8 == 3  a signed descriptor record (one of four fixed keys), chatput
//   op % 8 == 4  a signed epoch-keys record (one of four fixed keys), chatput
//   op % 8 == 5  chatget with queries built from fields
//   op % 8 == 6  getdata / inv for a record id seen earlier in this input
//   op % 8 == 7  getchatinv or getchatdir
//
// What is checked after every message, beyond the sanitizers:
//   - a record that parses serializes back to the same bytes;
//   - chatack carries a known result, and ACCEPTED means the node now has it
//     and the record was within its time bounds;
//   - a chatrecs answer has one entry per question (at most 32), at most
//     CHAT_MAX_ANSWER_BYTES in all, every record parses, matches the kind and
//     key asked for, an envelope answer is at most 64 records and none older
//     than "since", a signed kind answers at most one;
//   - the store's envelope bytes stay within their budget.
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a starting corpus and exits.

#include "headers_core.h"
#include "chatrelay.h"
#include "chatstore.h"
#include "btfchatbox.h"
#include "btfaddr.h"

#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <set>
#include <string>
#include <vector>

static void FuzzChatRelayInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzChatRelayInit
#include "fuzz_datadir.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

using btfchat::ChatRecord;
using btfchat::ChatStore;

static const unsigned int FUZZ_BITS = 4;
static secp256k1_context* g_ctx = NULL;
static const int NUM_KEYS = 4;
static btfchat::Identity g_ids[NUM_KEYS];

static const char* const kCommands[] = {
    "chatrec", "chatput", "chatget", "getchatinv", "getchatdir", "inv", "getdata", "chatack",
};
static const size_t kNumCommands = sizeof(kCommands) / sizeof(kCommands[0]);

static void MakeIdentity(int i, btfchat::Identity& id)
{
    memset(&id, 0, sizeof(id));
    for (int k = 0; k < 32; k++)
        id.sign_sk[k] = (unsigned char)(0x11 * (i + 1) + k);
    secp256k1_keypair kp;
    if (!secp256k1_keypair_create(g_ctx, &kp, id.sign_sk))
        abort();
    secp256k1_xonly_pubkey xpub;
    secp256k1_keypair_xonly_pub(g_ctx, &xpub, NULL, &kp);
    secp256k1_xonly_pubkey_serialize(g_ctx, id.sign_pk, &xpub);
    for (int k = 0; k < 32; k++)
        id.chan_sk[k] = (unsigned char)(0x5a ^ (i * 7 + k));
    btf::ChanPublicFromSecret(id.chan_pk, id.chan_sk);
    id.address = btf::Address(id.sign_pk);
}

// Deterministic mining to FUZZ_BITS: the nonce counts up from zero, so an
// input always builds the same record.
static void Mine(ChatRecord& r)
{
    r.nNonce = 0;
    while (!btfchat::ChatRecordHasWork(r, FUZZ_BITS))
        r.nNonce++;
}

// A little reader over the operation body.
struct Reader
{
    const uint8_t* p;
    size_t n;
    Reader(const uint8_t* pIn, size_t nIn) : p(pIn), n(nIn) {}
    uint8_t U8() { if (!n) return 0; n--; return *p++; }
    uint16_t U16() { uint16_t a = U8(); return (uint16_t)(a | (U8() << 8)); }
    int64_t S16() { return (int16_t)U16(); }
    std::vector<unsigned char> Bytes(size_t k)
    {
        if (k > n) k = n;
        std::vector<unsigned char> v(p, p + k);
        p += k;
        n -= k;
        return v;
    }
    std::string Str(size_t k) { std::vector<unsigned char> v = Bytes(k); return std::string(v.begin(), v.end()); }
};

static std::vector<std::vector<unsigned char> > g_keysSeen;   // record keys used in this input
static std::vector<uint256> g_idsSeen;                       // record ids seen in this input

static void NoteRecord(const ChatRecord& r)
{
    unsigned char id[32];
    r.Id(id);
    uint256 h;
    memcpy(h.begin(), id, 32);
    if (g_idsSeen.size() < 64)
        g_idsSeen.push_back(h);
    if (g_keysSeen.size() < 64)
        g_keysSeen.push_back(r.key);
}

// Parse what the node sent back and check it (see the top).
static void CheckOutput(CNode& node, const std::vector<CChatQuery>* pLastQuery, const ChatRecord* pPut)
{
    unsigned int nHdr = CMessageHeader::SizeOnWire(node.vSend.GetVersion());
    while (node.vSend.size() >= nHdr)
    {
        CDataStream h(node.vSend.begin(), node.vSend.begin() + nHdr, SER_NETWORK, node.vSend.GetVersion());
        CMessageHeader hdr;
        h >> hdr;
        if (node.vSend.size() < nHdr + hdr.nMessageSize)
            abort();   // the node never leaves half a message
        CDataStream pay(node.vSend.begin() + nHdr, node.vSend.begin() + nHdr + hdr.nMessageSize,
                        SER_NETWORK, VERSION);
        node.vSend.ignore((int)(nHdr + hdr.nMessageSize));
        std::string cmd = hdr.GetCommand();

        if (cmd == "chatack")
        {
            unsigned int nReq = 0;
            std::vector<unsigned char> vId;
            int nResult = -1;
            std::string why;
            pay >> nReq >> vId >> nResult >> why;
            if (nResult < ChatStore::REJECTED || nResult > ChatStore::DUPLICATE || vId.size() != 32)
                abort();
            if (nResult == ChatStore::ACCEPTED)
            {
                uint256 hId;
                memcpy(hId.begin(), &vId[0], 32);
                if (!ChatRelayAlreadyHave(CInv(MSG_CHATREC, hId)))
                    abort();   // taken but not held
                if (pPut)
                {
                    int64 nNow = GetAdjustedTime();
                    if (pPut->nTime > nNow + btfchat::CHATREC_MAX_FUTURE + 5)
                        abort();   // a record from the future was taken
                    std::string why2;
                    if (!btfchat::ChatRecordWellFormed(*pPut, why2) ||
                        !btfchat::ChatRecordHasWork(*pPut, FUZZ_BITS))
                        abort();
                }
            }
        }
        else if (cmd == "chatrecs")
        {
            unsigned int nReq = 0;
            std::vector<std::vector<std::vector<unsigned char> > > vAnswer;
            pay >> nReq >> vAnswer;
            if (vAnswer.size() > CHAT_MAX_QUERIES_PER_MSG)
                abort();
            if (pLastQuery && vAnswer.size() != std::min<size_t>(pLastQuery->size(), CHAT_MAX_QUERIES_PER_MSG))
                abort();   // answers out of line with the questions
            size_t nBytes = 0;
            for (size_t q = 0; q < vAnswer.size(); q++)
            {
                if (vAnswer[q].size() > btfchat::CHATREC_MAX_QUERY)
                    abort();
                for (size_t k = 0; k < vAnswer[q].size(); k++)
                {
                    const std::vector<unsigned char>& w = vAnswer[q][k];
                    nBytes += w.size();
                    ChatRecord r;
                    if (w.empty() || !r.Parse(&w[0], w.size()) || r.Serialize() != w)
                        abort();
                    if (pLastQuery)
                    {
                        const CChatQuery& cq = (*pLastQuery)[q];
                        if (r.kind != cq.kind || r.key != cq.key)
                            abort();   // an answer to another question
                        if (r.kind == btfchat::CHATREC_ENVELOPE)
                        {
                            if (r.nTime < cq.nSince || (cq.nMax >= 0 && k >= (size_t)cq.nMax))
                                abort();
                        }
                        else if (k > 0)
                            abort();   // a signed kind has one current record
                    }
                }
            }
            if (nBytes > CHAT_MAX_ANSWER_BYTES)
                abort();
        }
        else if (cmd == "chatrec")
        {
            std::vector<unsigned char> blob;
            pay >> blob;
            ChatRecord r;
            if (blob.empty() || !r.Parse(&blob[0], blob.size()) || r.Serialize() != blob)
                abort();
        }
    }
    size_t nRecords = 0, nEnvelopeBytes = 0;
    ChatRelayStats(nRecords, nEnvelopeBytes);
    if (nEnvelopeBytes > btfchat::CHATREC_ENVELOPE_BUDGET)
        abort();
}

static void Handle(CNode& node, const std::string& strCommand, CDataStream& vMsg)
{
    try
    {
        CRITICAL_BLOCK(cs_main)
            ProcessMessage(&node, strCommand, vMsg);
    }
    catch (...)
    {
        // A short or malformed payload ends that message, as in ProcessMessages.
    }
}

static void SendRecord(CNode& node, const ChatRecord& r, bool fRelay, unsigned int nReq)
{
    NoteRecord(r);
    std::vector<unsigned char> blob = r.Serialize();
    if (!fRelay)
    {
        CDataStream ss(SER_NETWORK, VERSION);
        ss << nReq << blob;
        Handle(node, "chatput", ss);
        CheckOutput(node, NULL, &r);
        return;
    }
    unsigned char id[32];
    r.Id(id);
    uint256 h;
    memcpy(h.begin(), id, 32);
    {
        CDataStream ss(SER_NETWORK, VERSION);
        ss << std::vector<CInv>(1, CInv(MSG_CHATREC, h));
        Handle(node, "inv", ss);
        node.mapAskFor.clear();   // nothing here sends the getdata
    }
    CDataStream ss(SER_NETWORK, VERSION);
    ss << blob;
    Handle(node, "chatrec", ss);
    CheckOutput(node, NULL, NULL);
}

static ChatRecord EnvelopeFrom(Reader& rd)
{
    ChatRecord r;
    uint8_t b = rd.U8();
    r.kind = (b & 0x80) ? (uint8_t)rd.U8() : (uint8_t)btfchat::CHATREC_ENVELOPE;
    size_t nKey = (b & 0x40) ? (size_t)(rd.U8() % 40) : btfchat::CHATREC_TAG_KEY_BYTES;
    if ((b & 0x20) && !g_keysSeen.empty())
        r.key = g_keysSeen[rd.U8() % g_keysSeen.size()];
    else
    {
        r.key = rd.Bytes(nKey);
        r.key.resize(nKey, 0);
    }
    // Time: minutes from now, either way, or far past and far future.
    int64_t nOff = rd.S16() * 60;
    if (b & 0x10)
        nOff *= 64;
    r.nTime = GetAdjustedTime() + nOff;
    size_t nPay = rd.U16();
    if (b & 0x08)
        nPay = nPay * 4;           // up to past the 64 KB cap
    r.payload = rd.Bytes(nPay);
    if (r.payload.size() < nPay && (b & 0x04))
        r.payload.resize(nPay, 0x5a);
    Mine(r);
    return r;
}

// Text for a field that goes into JSON: SignDescriptor dumps it, and nlohmann
// refuses bytes that are not UTF-8. The node signs strings of its own (an
// onion address, a key); only this harness builds them from raw bytes.
static std::string Text(std::string s)
{
    for (size_t i = 0; i < s.size(); i++)
        if ((unsigned char)s[i] >= 0x80)
            s[i] = '?';
    return s;
}

static ChatRecord DescriptorFrom(Reader& rd)
{
    const btfchat::Identity& id = g_ids[rd.U8() % NUM_KEYS];
    uint8_t b = rd.U8();
    int64_t nCreated = GetAdjustedTime() + rd.S16() * 60;
    std::string onion = (b & 1) ? Text(rd.Str(rd.U8()))
                                : "btjui62nrnc4ysmqkfxkkastvn65mecgf4j6qn2fxll3ayc7lb2vkuid.onion:8533";
    std::string enc = (b & 2) ? Text(rd.Str(rd.U8())) : HexStr(id.chan_pk, id.chan_pk + 32, false);
    std::string desc = btf::SignDescriptor(g_ctx, id.sign_sk, enc, (b & 4) ? Text(rd.Str(rd.U8())) : std::string(),
                                           (uint64_t)nCreated, onion);
    ChatRecord r;
    r.kind = btfchat::CHATREC_DESC;
    r.key.assign(id.sign_pk, id.sign_pk + 32);
    r.nTime = (b & 8) ? nCreated + rd.S16() : nCreated;
    r.payload.assign(desc.begin(), desc.end());
    if (b & 16)
    {
        std::vector<unsigned char> extra = rd.Bytes(rd.U8());
        if (!extra.empty() && !r.payload.empty())
            r.payload[extra[0] % r.payload.size()] ^= 1;   // a signed byte changed
    }
    Mine(r);
    return r;
}

static ChatRecord EpochFrom(Reader& rd)
{
    const btfchat::Identity& id = g_ids[rd.U8() % NUM_KEYS];
    uint8_t b = rd.U8();
    btfchat::EpochKeys k;
    k.epoch = btfchat::MailboxEpoch(GetAdjustedTime()) + (int8_t)rd.U8() % 4;
    std::vector<unsigned char> x = rd.Bytes(32);
    x.resize(32, 0x42);
    memcpy(k.x_pk, &x[0], 32);
    for (int i = 0; i < btf::CHAN_KEM_PUBBYTES; i++)
        k.kem_pk[i] = (unsigned char)(i * 13 + b);
    std::string js, err;
    btfchat::SignEpochKeys(g_ctx, id, k, js, err);
    ChatRecord r;
    r.kind = btfchat::CHATREC_EPOCH;
    r.key.assign(id.sign_pk, id.sign_pk + 32);
    r.nTime = (b & 1) ? GetAdjustedTime() + rd.S16() : k.epoch * btfchat::MAILBOX_EPOCH_SECONDS;
    r.payload.assign(js.begin(), js.end());
    Mine(r);
    return r;
}

static void WriteFile(const std::string& strPath, const std::string& data)
{
    FILE* f = fopen(strPath.c_str(), "wb");
    if (!f)
    {
        perror(strPath.c_str());
        exit(1);
    }
    fwrite(data.data(), 1, data.size(), f);
    fclose(f);
}

static void Op(std::string& s, uint8_t op, const std::string& body)
{
    s += (char)op;
    s += (char)(body.size() & 0xff);
    s += (char)((body.size() >> 8) & 0xff);
    s += body;
}

static void WriteSeeds(const std::string& dir)
{
    std::string s;
    // An envelope put, the same again (duplicate), a query for its tag.
    std::string env;
    env += (char)0x20;                 // reuse a key if one was seen
    env += std::string(16, 'T');
    env += std::string("\x00\x00", 2); // now
    env += std::string("\x40\x00", 2); // 64-byte payload
    env += std::string(64, 'p');
    std::string envFresh = env;
    envFresh[0] = 0;                   // a fresh key
    Op(s, 1, envFresh);
    Op(s, 1, envFresh);
    Op(s, 5, std::string("\x01\x00\x03\x00\x00\x40", 6));
    WriteFile(dir + "/envelope-put-query", s);

    s.clear();
    Op(s, 2, envFresh);                // announced and relayed
    Op(s, 6, std::string("\x00\x00", 2));
    Op(s, 7, std::string("\x00", 1));
    WriteFile(dir + "/envelope-relay-getdata", s);

    s.clear();
    Op(s, 3, std::string("\x00\x00\x00\x00", 4));
    Op(s, 3, std::string("\x00\x00\x01\x00", 4));   // a newer one supersedes
    Op(s, 5, std::string("\x01\x01\x01\x00\x00\x01", 6));
    WriteFile(dir + "/descriptor-supersede", s);

    s.clear();
    Op(s, 4, std::string("\x01\x00\x00", 3));
    Op(s, 5, std::string("\x01\x02\x01\x00\x00\x01", 6));
    WriteFile(dir + "/epoch-keys", s);

    // Sixty-five envelopes under one tag: the per-tag ceiling.
    s.clear();
    for (int i = 0; i < 65; i++)
    {
        std::string e = env;
        e[0] = (char)(i == 0 ? 0 : 0x20);
        e[17] = (char)(i - 32);        // spread the times
        Op(s, 1, e);
    }
    WriteFile(dir + "/tag-ceiling", s);

    // Raw messages: an empty chatget, a getchatinv, a chatrec never announced.
    s.clear();
    Op(s, 0, std::string("\x02\x00\x00\x00\x00\x00", 6));
    Op(s, 0, std::string("\x03", 1));
    Op(s, 0, std::string("\x04\x07\x00\x00\x00", 5));
    WriteFile(dir + "/raw", s);
}

static void FuzzChatRelayInit()
{
    SelectChainParams(false);
    if (!LoadBlockIndex())
    {
        fprintf(stderr, "fuzz-chat-relay: LoadBlockIndex failed\n");
        abort();
    }
    btf::ChanInit();
    g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    for (int i = 0; i < NUM_KEYS; i++)
        MakeIdentity(i, g_ids[i]);
    nLocalServices |= NODE_CHAT;

    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        exit(0);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > 300000)
        return 0;
    ChatRelayFuzzReset(FUZZ_BITS);
    g_keysSeen.clear();
    g_idsSeen.clear();

    CNode node(INVALID_SOCKET, CAddress("127.0.0.1"));
    node.nVersion = VERSION;
    node.nServices = NODE_NETWORK | NODE_CHAT;
    node.vSend.clear();       // the version message an outbound node queues when it is made
    node.vSend.SetVersion(VERSION);
    node.vRecv.SetVersion(VERSION);

    unsigned int nReq = 0;
    for (int nOps = 0; nOps < 96 && size >= 3; nOps++)
    {
        uint8_t op = data[0];
        size_t nLen = data[1] | ((size_t)data[2] << 8);
        data += 3;
        size -= 3;
        if (nLen > size)
            nLen = size;
        Reader rd(data, nLen);
        data += nLen;
        size -= nLen;
        nReq++;

        switch (op % 8)
        {
        case 0:
        {
            std::string cmd = kCommands[rd.U8() % kNumCommands];
            std::vector<unsigned char> body = rd.Bytes(rd.n);
            CDataStream ss((const char*)(body.empty() ? NULL : &body[0]),
                           (const char*)(body.empty() ? NULL : &body[0] + body.size()), SER_NETWORK, VERSION);
            Handle(node, cmd, ss);
            CheckOutput(node, NULL, NULL);
            // A raw chatrec body is a record: check its own round trip.
            if (!body.empty())
            {
                ChatRecord r;
                if (r.Parse(&body[0], body.size()) && r.Serialize() != body)
                    abort();
            }
            break;
        }
        case 1:
        case 2:
        {
            ChatRecord r = EnvelopeFrom(rd);
            SendRecord(node, r, (op % 8) == 2, nReq);
            break;
        }
        case 3:
            SendRecord(node, DescriptorFrom(rd), false, nReq);
            break;
        case 4:
            SendRecord(node, EpochFrom(rd), false, nReq);
            break;
        case 5:
        {
            std::vector<CChatQuery> vq;
            size_t nq = rd.U8() % 40;
            for (size_t i = 0; i < nq; i++)
            {
                CChatQuery q;
                q.kind = (uint8_t)(rd.U8() % 5);
                uint8_t sel = rd.U8();
                if (!g_keysSeen.empty() && sel < 200)
                    q.key = g_keysSeen[sel % g_keysSeen.size()];
                else
                    q.key = rd.Bytes(sel % 40);
                q.nSince = (rd.U8() & 1) ? GetAdjustedTime() + rd.S16() * 60 : rd.S16();
                q.nMax = (int)(int16_t)rd.U16();
                vq.push_back(q);
            }
            CDataStream ss(SER_NETWORK, VERSION);
            ss << nReq << vq;
            Handle(node, "chatget", ss);
            CheckOutput(node, &vq, NULL);
            break;
        }
        case 6:
        {
            if (g_idsSeen.empty())
                break;
            uint256 h = g_idsSeen[rd.U8() % g_idsSeen.size()];
            CDataStream ss(SER_NETWORK, VERSION);
            ss << std::vector<CInv>(1 + rd.U8() % 3, CInv(MSG_CHATREC, h));
            Handle(node, (rd.U8() & 1) ? "inv" : "getdata", ss);
            node.mapAskFor.clear();
            CheckOutput(node, NULL, NULL);
            break;
        }
        case 7:
        {
            CDataStream ss(SER_NETWORK, VERSION);
            bool fDir = rd.U8() & 1;
            if (fDir)
                ss << nReq;
            if (rd.U8() & 1)
                node.nLastChatInvAsked = 0;   // as if ten minutes had passed
            Handle(node, fDir ? "getchatdir" : "getchatinv", ss);
            CheckOutput(node, NULL, NULL);
            break;
        }
        }
    }
    return 0;
}
