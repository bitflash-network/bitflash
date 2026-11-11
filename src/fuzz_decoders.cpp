// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Fuzz harness for the text decoders: what a person, a payment link, a QR
// code, an RPC caller or a peer hands the node as a string. One harness, one
// selector byte:
//
//   byte 0   which decoder, an index into kDecoders (modulo its size)
//   rest     the text (or, for the encode-first entries, the bytes)
//
// Each entry calls the real function the node calls and, where there is an
// encoder for the same format, checks the pair: encode(decode(s)) gives back
// s in its normal form (trimmed, lower case where the format ignores case),
// and decode(encode(b)) gives back b. Where the node has two parsers for the
// same thing (three amount parsers; the two Bitflash address readers) they
// must agree whenever both accept. Any violation aborts.
//
// Not here because the node has no such parser: BIP32 extended keys
// (xprv/xpub) and derivation paths written as text. Keys are derived from a
// seed and a path of numbers, which the BIP32 entry exercises.
//
// BITFLASH_FUZZ_WRITE_SEEDS=<dir> writes a starting corpus and exits.

#include "headers_core.h"
#include "btfaddr.h"
#include "bip32.h"
#include "bip39_english.h"
#include "bip21.h"
#include "invoice.h"
#include "coinunit.h"
#include "btcswap.h"
#include "btclight.h"

#ifndef SECP256K1_STATIC
#define SECP256K1_STATIC
#endif
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <exception>
#include <string>
#include <vector>

static void FuzzDecodersInit();
#define BITFLASH_FUZZ_INIT_EXTRA FuzzDecodersInit
#include "fuzz_datadir.h"

// Stand-ins normally supplied by the GUI/headless entry objects.
map<string,string> mapAddressBook;
bool gPoolServerRunning = false;
void MainFrameRepaint() {}

static secp256k1_context* g_ctx = NULL;
static unsigned char g_seckey[32];
static unsigned char g_pubkey[32];

static void Fail(const char* pszWhat, const string& strInput)
{
    fprintf(stderr, "fuzz-decoders: %s\n  input: %s\n", pszWhat,
            HexStr(strInput.begin(), strInput.end(), false).c_str());
    abort();
}

static bool IsSpace(char c) { return isspace((unsigned char)c) != 0; }

static string TrimSpace(const string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && IsSpace(s[a])) a++;
    while (b > a && IsSpace(s[b - 1])) b--;
    return s.substr(a, b - a);
}

static string Lower(const string& s)
{
    string r = s;
    for (size_t i = 0; i < r.size(); i++)
        r[i] = (char)tolower((unsigned char)r[i]);
    return r;
}

// btfaddr.cpp's ToLowerTrim: what a .btf name is compared in.
static string BtfNormal(const string& in)
{
    size_t a = in.find_first_not_of(" \t\r\n");
    size_t b = in.find_last_not_of(" \t\r\n");
    if (a == string::npos)
        return string();
    string s = in.substr(a, b - a + 1);
    while (!s.empty() && s[s.size() - 1] == '.')
        s.erase(s.size() - 1);
    return Lower(s);
}

// ---- base58 and Bitflash addresses -------------------------------------------

// The base58 readers take C strings: they see the input up to its first NUL.
static string CStr(const string& s)
{
    return s.substr(0, s.find('\0'));
}

static void Base58(const string& sIn)
{
    string s = CStr(sIn);
    vector<unsigned char> v;
    if (!DecodeBase58(s, v))
        return;
    // DecodeBase58 skips leading white space and stops at trailing white space.
    string enc = EncodeBase58(v.empty() ? NULL : &v[0], v.empty() ? NULL : &v[0] + v.size());
    if (enc != TrimSpace(s))
        Fail("base58: encode(decode(s)) != s", s);
}

static void Base58Bytes(const string& s)
{
    vector<unsigned char> v(s.begin(), s.end()), v2;
    string enc = EncodeBase58(v);
    if (!DecodeBase58(enc, v2) || v2 != v)
        Fail("base58: decode(encode(b)) != b", s);
    string encc = EncodeBase58Check(v);
    if (!DecodeBase58Check(encc, v2) || v2 != v)
        Fail("base58check: decode(encode(b)) != b", s);
}

static void Base58Check(const string& sIn)
{
    string s = CStr(sIn);
    vector<unsigned char> v;
    if (!DecodeBase58Check(s, v))
        return;
    if (EncodeBase58Check(v) != TrimSpace(s))
        Fail("base58check: encode(decode(s)) != s", s);
}

static void BitflashAddress(const string& sIn)
{
    string s = CStr(sIn);
    uint160 h1, h2;
    bool fScript = false;
    bool fKey = AddressToHash160(s, h1);
    bool fAny = DecodeAnyAddress(s, h2, fScript);
    if (fKey && (!fAny || fScript || h1 != h2))
        Fail("address: AddressToHash160 and DecodeAnyAddress disagree", s);
    if (fAny && !fScript && !fKey)
        Fail("address: DecodeAnyAddress took a key address AddressToHash160 refuses", s);
    if (IsValidBitcoinAddress(s) != fKey)
        Fail("address: IsValidBitcoinAddress disagrees with AddressToHash160", s);
    if (fAny)
    {
        string enc = fScript ? Hash160ToScriptAddress(h2) : Hash160ToAddress(h2);
        if (enc != TrimSpace(s))
            Fail("address: encode(decode(s)) != s", s);
    }
}

static void BitflashAddressBytes(const string& s)
{
    if (s.size() < 20)
        return;
    uint160 h;
    memcpy(&h, s.data(), 20);
    uint160 h2;
    bool fScript = true;
    if (!AddressToHash160(Hash160ToAddress(h), h2) || h2 != h)
        Fail("address: key hash does not survive encode/decode", s);
    if (!DecodeAnyAddress(Hash160ToAddress(h), h2, fScript) || fScript || h2 != h)
        Fail("address: DecodeAnyAddress misreads a key address", s);
    if (!DecodeAnyAddress(Hash160ToScriptAddress(h), h2, fScript) || !fScript || h2 != h)
        Fail("address: script hash does not survive encode/decode", s);
    if (AddressToHash160(Hash160ToScriptAddress(h), h2))
        Fail("address: AddressToHash160 took a script address", s);
}

// ---- .btf names ---------------------------------------------------------------

static void BtfName(const string& s)
{
    unsigned char pk[32];
    int nVersion = 0;
    bool fOk = btf::ParseAddressVersion(s, pk, nVersion);
    unsigned char pk1[32];
    bool fV1 = btf::ParseAddress(s, pk1);
    if (fV1 != (fOk && nVersion == btf::ADDR_VERSION_XONLY))
        Fail("btf: ParseAddress disagrees with ParseAddressVersion", s);
    if (fV1 && memcmp(pk, pk1, 32) != 0)
        Fail("btf: ParseAddress and ParseAddressVersion read different keys", s);
    if (fOk)
    {
        if (!btf::IsBtf(s))
            Fail("btf: parsed a name IsBtf says is not one", s);
        // One key, one version, one name.
        if (btf::AddressVersioned(pk, nVersion) != BtfNormal(s))
            Fail("btf: the name is not the one its key and version encode to", s);
    }
}

static void BtfNameBytes(const string& s)
{
    if (s.size() < 33)
        return;
    unsigned char pk[32], pk2[32];
    memcpy(pk, s.data(), 32);
    int nVersion = (unsigned char)s[32], nVersion2 = 0;
    string name = btf::AddressVersioned(pk, nVersion);
    if (!btf::ParseAddressVersion(name, pk2, nVersion2) || memcmp(pk, pk2, 32) != 0 ||
        nVersion2 != (nVersion <= btf::ADDR_VERSION_XONLY ? btf::ADDR_VERSION_XONLY : nVersion))
        Fail("btf: key and version do not survive encode/decode", s);
    vector<unsigned char> raw;
    if (!btf::Base32Decode(btf::Base32Encode((const unsigned char*)s.data(), s.size()), raw) ||
        raw != vector<unsigned char>(s.begin(), s.end()))
        Fail("base32: decode(encode(b)) != b", s);
}

static void OnionEndpoint(const string& s)
{
    string out, out2;
    if (!btf::NormalizeOnionEndpoint(s, out))
        return;
    if (!btf::NormalizeOnionEndpoint(out, out2) || out2 != out)
        Fail("onion: normal form is not stable", s);
    // The normal form names the port the way a number is written.
    size_t colon = out.rfind(':');
    if (colon == string::npos || out[colon + 1] == '0')
        Fail("onion: port with a leading zero in the normal form", s);
}

static void Descriptor(const string& s)
{
    btf::Descriptor d;
    if (!btf::VerifyDescriptor(g_ctx, s, g_pubkey, d))
        return;
    if (memcmp(d.pubkey, g_pubkey, 32) != 0)
        Fail("descriptor: accepted for another key", s);
    // The key and the signature were read as hex: two digits per byte and
    // nothing else, or one descriptor has many spellings.
    nlohmann::json j = nlohmann::json::parse(s);
    const char* kHex[] = { "pubkey", "sig" };
    for (int i = 0; i < 2; i++)
    {
        string h = j[kHex[i]].get<string>();
        for (size_t k = 0; k < h.size(); k++)
            if (!isxdigit((unsigned char)h[k]))
                Fail("descriptor: a hex field that is not plain hex was accepted", s);
    }
    if (!d.onion.empty())
    {
        string norm;
        if (!btf::NormalizeOnionEndpoint(d.onion, norm) || norm != d.onion)
            Fail("descriptor: onion endpoint not in normal form", s);
    }
}

// ---- BIP39 and BIP32 ----------------------------------------------------------

static void Bip39Text(const string& s)
{
    string norm, err;
    if (!bitflash::BIP39ValidateMnemonic(s, norm, err))
        return;
    string norm2;
    if (!bitflash::BIP39ValidateMnemonic(norm, norm2, err) || norm2 != norm)
        Fail("bip39: normal form is not stable", s);
}

// Words picked by 11-bit indices from the input, separated and cased by the
// input too, so the checksum is met one time in 2^(words/3).
static void Bip39Words(const string& s)
{
    if (s.size() < 2)
        return;
    static const int kCounts[] = { 12, 15, 18, 21, 24 };
    int nWords = kCounts[(unsigned char)s[0] % 5];
    const unsigned char* p = (const unsigned char*)s.data() + 1;
    size_t n = s.size() - 1;
    if (n * 8 < (size_t)nWords * 11)
        return;
    vector<int> idx(nWords);
    for (int w = 0; w < nWords; w++)
    {
        int v = 0;
        for (int b = 0; b < 11; b++)
        {
            size_t bit = (size_t)w * 11 + b;
            v = (v << 1) | ((p[bit / 8] >> (7 - bit % 8)) & 1);
        }
        idx[w] = v;
    }
    // Separator and case from whatever is left.
    const unsigned char* q = p + (nWords * 11 + 7) / 8;
    size_t nq = n - (nWords * 11 + 7) / 8;
    static const char* kSep[] = { " ", "  ", "\t", "\n", " \r\n " };
    string phrase = nq && (q[0] & 0x80) ? "  " : "";
    for (int w = 0; w < nWords; w++)
    {
        string word = bitflash::BIP39_ENGLISH_WORDS[idx[w]];
        unsigned char c = w + 1 < (int)nq ? q[w + 1] : 0;
        if (c & 1)
            for (size_t i = 0; i < word.size(); i++)
                word[i] = (char)toupper((unsigned char)word[i]);
        if (w)
            phrase += kSep[(c >> 1) % 5];
        phrase += word;
    }

    string norm, err;
    bool fOk = bitflash::BIP39ValidateMnemonic(phrase, norm, err);

    // The same words, lower case, single spaces: what the normal form is.
    string expect;
    for (int w = 0; w < nWords; w++)
        expect += string(w ? " " : "") + bitflash::BIP39_ENGLISH_WORDS[idx[w]];
    if (norm != expect)
        Fail("bip39: normal form is not the words joined by single spaces", phrase);

    // The checksum, computed here independently.
    size_t nBits = nWords * 11, nEnt = nBits * 32 / 33, nCs = nBits - nEnt;
    vector<unsigned char> entropy(nEnt / 8, 0);
    vector<bool> bits;
    for (int w = 0; w < nWords; w++)
        for (int b = 10; b >= 0; b--)
            bits.push_back((idx[w] >> b) & 1);
    for (size_t i = 0; i < nEnt; i++)
        if (bits[i])
            entropy[i / 8] |= (unsigned char)(0x80 >> (i % 8));
    unsigned char hash[32];
    SHA256(&entropy[0], entropy.size(), hash);
    bool fExpect = true;
    for (size_t i = 0; i < nCs; i++)
        if (bits[nEnt + i] != (((hash[i / 8] >> (7 - i % 8)) & 1) != 0))
            fExpect = false;
    if (fOk != fExpect)
        Fail("bip39: checksum verdict differs from the independent computation", phrase);
    if (fOk)
    {
        string mnemonic;
        if (!bitflash::BIP39EntropyToMnemonic(entropy, mnemonic, err) || mnemonic != norm)
            Fail("bip39: entropy does not encode back to the phrase", phrase);
    }
}

static void Bip39Entropy(const string& s)
{
    if (s.size() < 1)
        return;
    static const size_t kSizes[] = { 16, 20, 24, 28, 32 };
    size_t nEnt = kSizes[(unsigned char)s[0] % 5];
    if (s.size() < 1 + nEnt)
        return;
    vector<unsigned char> entropy(s.begin() + 1, s.begin() + 1 + nEnt);
    string mnemonic, norm, err;
    if (!bitflash::BIP39EntropyToMnemonic(entropy, mnemonic, err))
        Fail("bip39: entropy of a supported size refused", s);
    if (!bitflash::BIP39ValidateMnemonic(mnemonic, norm, err) || norm != mnemonic)
        Fail("bip39: a generated phrase does not validate", s);
    // The seed takes 2048 rounds of PBKDF2; only when asked.
    if (s[0] & 0x80)
    {
        vector<unsigned char> seed, seed2;
        string pass(s.begin() + 1 + nEnt, s.end());
        if (!bitflash::BIP39MnemonicToSeed(mnemonic, pass, seed, err) || seed.size() != 64)
            Fail("bip39: seed derivation failed on a valid phrase", s);
        // Case and spacing do not change the seed.
        string loud = "  " + mnemonic + "\n";
        for (size_t i = 0; i < loud.size(); i++)
            loud[i] = (char)toupper((unsigned char)loud[i]);
        if (!bitflash::BIP39MnemonicToSeed(loud, pass, seed2, err) || seed2 != seed)
            Fail("bip39: seed depends on case or spacing", s);
    }
}

static void Bip32(const string& s)
{
    if (s.size() < 2)
        return;
    size_t nSeed = (unsigned char)s[0] % 64 + 1;     // 1..64, so short ones are refused
    if (s.size() < 1 + nSeed)
        return;
    vector<unsigned char> seed(s.begin() + 1, s.begin() + 1 + nSeed);
    bitflash::BIP32PrivateNode master;
    string err;
    bool fOk = bitflash::BIP32MasterFromSeed(seed, master, err);
    if (fOk && nSeed < 16)
        Fail("bip32: master key from a seed shorter than 128 bits", s);
    if (!fOk)
        return;
    if (master.privateKey.size() != 32 || master.chainCode.size() != 32)
        Fail("bip32: master node of the wrong shape", s);

    vector<unsigned int> path;
    for (size_t i = 1 + nSeed; i + 4 <= s.size() && path.size() < 6; i += 4)
    {
        unsigned int c;
        memcpy(&c, s.data() + i, 4);
        path.push_back(c);
    }
    bitflash::BIP32PrivateNode viaPath, cur = master;
    bool fPath = bitflash::BIP32DerivePath(master, path, viaPath, err);
    bool fSteps = true;
    for (size_t i = 0; i < path.size() && fSteps; i++)
    {
        bitflash::BIP32PrivateNode next, hard;
        fSteps = bitflash::BIP32DeriveChild(cur, path[i], next, err);
        if (fSteps && path[i] >= bitflash::BIP32_HARDENED)
        {
            if (!bitflash::BIP32DeriveHardenedChild(cur, path[i] & ~bitflash::BIP32_HARDENED, hard, err) ||
                hard.privateKey != next.privateKey || hard.chainCode != next.chainCode)
                Fail("bip32: hardened helper disagrees with DeriveChild", s);
        }
        if (fSteps)
            cur = next;
    }
    if (fPath != fSteps)
        Fail("bip32: path and step-by-step derivation disagree on success", s);
    if (fPath && (viaPath.privateKey != cur.privateKey || viaPath.chainCode != cur.chainCode))
        Fail("bip32: path and step-by-step derivation give different keys", s);
}

// ---- payment links and amounts -------------------------------------------------

static bool SameLink(const PaymentLink& a, const PaymentLink& b)
{
    return a.address == b.address && a.amount == b.amount && a.label == b.label && a.message == b.message;
}

static void PaymentLinkText(const string& sIn)
{
    // Half the inputs get the scheme for free, so the fuzzer spends its time
    // on the query.
    string s = sIn;
    if (!s.empty() && (s[0] & 1))
        s = "bitflash:" + s.substr(1);
    PaymentLink link;
    string err;
    if (!ParsePaymentLink(s, link, err))
        return;
    if (link.amount < 0 || link.amount > (int64)21000000 * COIN)
        Fail("bip21: amount out of range", s);
    // The address is carried as written; the wallet checks it next. A real
    // one survives make/parse exactly, with everything else. Anything else
    // (white space, a leading "//" read as part of the scheme) may change
    // or vanish on the way, so only the other fields are compared, and only
    // if the link we made still parses.
    uint160 h;
    bool fScript;
    bool fReal = DecodeAnyAddress(link.address, h, fScript);
    PaymentLink link2;
    string made = MakePaymentLink(link);
    if (!ParsePaymentLink(made, link2, err))
    {
        if (fReal)
            Fail("bip21: a link we made does not parse", s);
        return;
    }
    PaymentLink a = link, b = link2;
    if (!fReal)
        a.address = b.address = "";
    if (!SameLink(a, b))
        Fail("bip21: parse(make(link)) != link", s);
}

static void Amounts(const string& s)
{
    int64 nMoney = 0, nCoin = 0;
    int64_t nCoin64 = 0;
    bool fMoney = ParseMoney(s.c_str(), nMoney);
    bool fCoin = ParseCoinAmount("btc", s, nCoin64);
    nCoin = nCoin64;
    if (memchr(s.data(), 0, s.size()))
        fMoney = false;             // ParseMoney sees a C string: a different input
    if (fMoney && (nMoney < 0))
        Fail("ParseMoney: negative amount", s);
    if (fCoin && (nCoin < 0 || nCoin > (int64)21000000 * COIN))
        Fail("ParseCoinAmount: out of range", s);
    if (fMoney && fCoin && nMoney != nCoin)
        Fail("ParseMoney and ParseCoinAmount read different amounts", s);

    // The payment link's amount grammar is the strictest: whatever it takes,
    // the other two take, and read the same.
    // (Not for text the link would decode or trim first.)
    if (s.find_first_of(string("%+&#\0 \t\r\n\v\f", 11)) == string::npos)
    {
        PaymentLink link;
        string err;
        if (ParsePaymentLink("bitflash:B?amount=" + s, link, err))
        {
            if (!fCoin || link.amount != nCoin)
                Fail("bip21 amount and ParseCoinAmount disagree", s);
            if (fMoney && link.amount != nMoney)
                Fail("bip21 amount and ParseMoney disagree", s);
        }
    }
}

static void AmountsFromNumber(const string& s)
{
    if (s.size() < 8)
        return;
    uint64 u;
    memcpy(&u, s.data(), 8);
    int64 n = (int64)(u % ((uint64)21000000 * COIN + 1));
    int64 nParsed = 0;
    int64_t nParsed64 = 0;
    // FormatMoney shows cents.
    if (!ParseMoney(FormatMoney(n).c_str(), nParsed) || nParsed != n - n % CENT)
        Fail("ParseMoney(FormatMoney(n)) != n to the cent", s);
    if (!ParseCoinAmount("btc", CoinAmountText("btc", n), nParsed64) || nParsed64 != n)
        Fail("ParseCoinAmount(CoinAmountText(n)) != n", s);
    if (!ParseCoinAmount("xec", CoinAmountText("xec", n), nParsed64) || nParsed64 != n)
        Fail("xec: ParseCoinAmount(CoinAmountText(n)) != n", s);
    PaymentLink link;
    link.address = Hash160ToAddress(uint160(7));
    link.amount = n;
    PaymentLink link2;
    string err;
    if (!ParsePaymentLink(MakePaymentLink(link), link2, err) || link2.amount != n)
        Fail("bip21: amount does not survive make/parse", s);
}

// ---- hex -------------------------------------------------------------------------

static void Hex(const string& s)
{
    vector<unsigned char> v = ParseHex(s);
    bool fHex = IsHex(s);
    if (fHex && v.empty())
        Fail("ParseHex: IsHex string gave no bytes", s);
    if (fHex && HexStr(v.begin(), v.end(), false) != Lower(s))
        Fail("hex: encode(decode(s)) != s", s);

    // The RPC's hash parser: lenient by design (0x, white space, short and
    // long strings), so only check it does not misbehave, and that a hash's
    // own hex reads back to it.
    uint256 h;
    h.SetHex(s);
    uint256 h2;
    h2.SetHex(h.GetHex());
    if (h2 != h)
        Fail("uint256: SetHex(GetHex()) != itself", s);
    uint160 k;
    k.SetHex(s);
    uint160 k2;
    k2.SetHex(k.GetHex());
    if (k2 != k)
        Fail("uint160: SetHex(GetHex()) != itself", s);
    if (s.size() == 64 && fHex)
    {
        if (h.GetHex() != Lower(s))
            Fail("uint256: 64 hex digits do not read back as written", s);
    }
}

static void InvoiceUrl(const string& s)
{
    string host, path;
    unsigned short port = 0;
    if (!invoice::ParseHttpUrl(s, host, port, path))
        return;
    if (host.empty() || port == 0 || path.empty() || path[0] != '/')
        Fail("invoice: ParseHttpUrl accepted a URL without host, port or path", s);
}

// ---- other chains' addresses -----------------------------------------------------

static void CashAddr(const string& sIn)
{
    if (sIn.empty())
        return;
    string prefix = (sIn[0] & 1) ? "ecash" : "bitcoincash";
    string s = sIn.substr(1);
    unsigned char nType = 0;
    vector<unsigned char> hash;
    if (!btcswap::CashDecode(prefix, s, nType, hash))
        return;
    string norm = Lower(s);
    if (norm.find(':') == string::npos)
        norm = prefix + ":" + norm;
    if (btcswap::CashEncode(prefix, nType, hash) != norm)
        Fail("cashaddr: encode(decode(s)) != s", sIn);
}

static void CashAddrBytes(const string& s)
{
    if (s.size() < 21)
        return;
    unsigned char nType = (unsigned char)s[0] & 0x0f;
    vector<unsigned char> hash(s.begin() + 1, s.begin() + ((s[0] & 0x10) && s.size() >= 33 ? 33 : 21));
    string enc = btcswap::CashEncode("bitcoincash", nType, hash);
    unsigned char nType2 = 0;
    vector<unsigned char> hash2;
    if (!btcswap::CashDecode("bitcoincash", enc, nType2, hash2) || nType2 != nType || hash2 != hash)
        Fail("cashaddr: decode(encode(b)) != b", s);
}

static void OtherChainDestination(const string& sIn)
{
    if (sIn.empty())
        return;
    static const char* kCoins[] = { "btc", "ltc", "doge", "bch", "xec", "dgb", "rvn" };
    btcswap::Chain chain;
    chain.coin = kCoins[(unsigned char)sIn[0] % 7];
    chain.fMain = (sIn[0] & 0x80) == 0;
    chain.name = chain.fMain ? "main" : "test";
    if (chain.coin == "bch")
        chain.cashPrefix = chain.fMain ? "bitcoincash" : "bchtest";
    else if (chain.coin == "xec")
        chain.cashPrefix = chain.fMain ? "ecash" : "ectest";
    CScript script;
    string err;
    btclight::Destination(chain, sIn.substr(1), script, err);
}

// ---- table ---------------------------------------------------------------------

typedef void (*DecoderFn)(const string&);
struct DecoderEntry
{
    const char* pszName;
    DecoderFn fn;
};

static const DecoderEntry kDecoders[] = {
    { "base58",              Base58 },
    { "base58-bytes",        Base58Bytes },
    { "base58check",         Base58Check },
    { "address",             BitflashAddress },
    { "address-bytes",       BitflashAddressBytes },
    { "btf",                 BtfName },
    { "btf-bytes",           BtfNameBytes },
    { "onion",               OnionEndpoint },
    { "descriptor",          Descriptor },
    { "bip39-text",          Bip39Text },
    { "bip39-words",         Bip39Words },
    { "bip39-entropy",       Bip39Entropy },
    { "bip32",               Bip32 },
    { "bip21",               PaymentLinkText },
    { "amount",              Amounts },
    { "amount-number",       AmountsFromNumber },
    { "hex",                 Hex },
    { "invoice-url",         InvoiceUrl },
    { "cashaddr",            CashAddr },
    { "cashaddr-bytes",      CashAddrBytes },
    { "destination",         OtherChainDestination },
};
static const size_t kNumDecoders = sizeof(kDecoders) / sizeof(kDecoders[0]);

static size_t DecoderIndex(const char* psz)
{
    for (size_t i = 0; i < kNumDecoders; i++)
        if (strcmp(kDecoders[i].pszName, psz) == 0)
            return i;
    fprintf(stderr, "fuzz-decoders: no decoder %s\n", psz);
    abort();
}

// ---- seeds -----------------------------------------------------------------------

static int g_nSeed = 0;

static void WriteSeed(const string& strDir, const char* pszDecoder, const string& s)
{
    string strPath = strDir + "/" + strprintf("%s-%03d", pszDecoder, g_nSeed++);
    FILE* f = fopen(strPath.c_str(), "wb");
    if (!f)
    {
        perror(strPath.c_str());
        exit(1);
    }
    unsigned char sel = (unsigned char)DecoderIndex(pszDecoder);
    fwrite(&sel, 1, 1, f);
    fwrite(s.data(), 1, s.size(), f);
    fclose(f);
}

static void WriteSeeds(const string& strDir)
{
    uint160 h(1234567);
    string strKeyAddr = Hash160ToAddress(h), strScriptAddr = Hash160ToScriptAddress(h);
    string b20(20, '\x5a');
    vector<unsigned char> v5(5, 0);
    v5[4] = 7;

    WriteSeed(strDir, "base58", strKeyAddr);
    WriteSeed(strDir, "base58", "  111" + EncodeBase58(v5) + " \n");
    WriteSeed(strDir, "base58-bytes", string("\0\0\x01\x02\xff", 5));
    WriteSeed(strDir, "base58check", strScriptAddr);
    WriteSeed(strDir, "address", strKeyAddr);
    WriteSeed(strDir, "address", strScriptAddr);
    WriteSeed(strDir, "address", " " + strKeyAddr + "\t");
    WriteSeed(strDir, "address-bytes", b20);

    string strBtf = btf::Address(g_pubkey);
    WriteSeed(strDir, "btf", strBtf);
    WriteSeed(strDir, "btf", btf::AddressVersioned(g_pubkey, 2));
    WriteSeed(strDir, "btf", " " + Lower(strBtf) + ".\n");
    WriteSeed(strDir, "btf-bytes", string((const char*)g_pubkey, 32) + "\x02");
    string strOnion = string(56, 'a') + ".onion:80";
    WriteSeed(strDir, "onion", strOnion);
    WriteSeed(strDir, "onion", " " + string(56, 'B') + ".ONION.:0443 ");
    WriteSeed(strDir, "descriptor", btf::SignDescriptor(g_ctx, g_seckey, string(64, 'e'), "abc.btf", 1790000000));
    WriteSeed(strDir, "descriptor", btf::SignDescriptor(g_ctx, g_seckey, string(64, 'e'), "abc.btf", 1790000000, strOnion));

    vector<unsigned char> ent(16, 0x7f);
    string mnemonic, err;
    bitflash::BIP39EntropyToMnemonic(ent, mnemonic, err);
    WriteSeed(strDir, "bip39-text", mnemonic);
    WriteSeed(strDir, "bip39-text", "  " + mnemonic + "\n");
    WriteSeed(strDir, "bip39-words", string(1, '\0') + string(17, '\x7f'));
    WriteSeed(strDir, "bip39-entropy", string(1, '\x80') + string(16, '\x7f') + "TREZOR");
    WriteSeed(strDir, "bip39-entropy", string(1, '\x04') + string(32, '\x01'));
    WriteSeed(strDir, "bip32", string(1, '\x0f') + string(16, '\x01') + string("\x00\x00\x00\x80\x01\x00\x00\x80\x00\x00\x00\x00\x05\x00\x00\x00", 16));
    WriteSeed(strDir, "bip32", string(1, '\x3f') + string(64, '\x02') + string("\x2c\x00\x00\x80", 4));

    WriteSeed(strDir, "bip21", "bitflash:" + strKeyAddr + "?amount=1.5&label=Shop%20one&message=order+42");
    WriteSeed(strDir, "bip21", "BITFLASH://" + strScriptAddr + "?amount=0.00000001&req-x=1");
    WriteSeed(strDir, "bip21", string("\x01") + strKeyAddr + "?label=a&&message=%zz");
    WriteSeed(strDir, "amount", "1.5");
    WriteSeed(strDir, "amount", "1,234,567.12345678");
    WriteSeed(strDir, "amount", " 21000000 ");
    WriteSeed(strDir, "amount", ".00000001");
    WriteSeed(strDir, "amount", "1.");
    WriteSeed(strDir, "amount-number", string("\x01\x02\x03\x04\x05\x06\x07\x00", 8));
    WriteSeed(strDir, "hex", "00ff10ab");
    WriteSeed(strDir, "hex", Hash(BEGIN(h), END(h)).GetHex());
    WriteSeed(strDir, "hex", "  0x1234 ");
    WriteSeed(strDir, "invoice-url", "http://127.0.0.1:8080/hook");
    WriteSeed(strDir, "invoice-url", "http://[::1]/x");

    vector<unsigned char> hash20(20, 0x11);
    WriteSeed(strDir, "cashaddr", "\x00" + btcswap::CashEncode("bitcoincash", 0, hash20));
    WriteSeed(strDir, "cashaddr", "\x01" + btcswap::CashEncode("ecash", 1, hash20).substr(6));
    WriteSeed(strDir, "cashaddr-bytes", string(1, '\x01') + string(20, '\x22'));
    WriteSeed(strDir, "destination", string(1, '\0') + "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    WriteSeed(strDir, "destination", string(1, '\0') + "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
    WriteSeed(strDir, "destination", string(1, '\x03') + btcswap::CashEncode("bitcoincash", 0, hash20));
}

static void FuzzDecodersInit()
{
    g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    for (int i = 0; i < 32; i++)
        g_seckey[i] = (unsigned char)(i + 1);
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpub;
    if (!secp256k1_keypair_create(g_ctx, &kp, g_seckey) ||
        !secp256k1_keypair_xonly_pub(g_ctx, &xpub, NULL, &kp) ||
        !secp256k1_xonly_pubkey_serialize(g_ctx, g_pubkey, &xpub))
    {
        fprintf(stderr, "fuzz-decoders: cannot make the descriptor key\n");
        abort();
    }
    const char* pszSeeds = getenv("BITFLASH_FUZZ_WRITE_SEEDS");
    if (pszSeeds && *pszSeeds)
    {
        WriteSeeds(pszSeeds);
        fprintf(stderr, "fuzz-decoders: seeds written to %s\n", pszSeeds);
        exit(0);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 1 || size > 8192)
        return 0;
    const DecoderEntry& e = kDecoders[data[0] % kNumDecoders];
    string s((const char*)data + 1, size - 1);
    // No catch: none of these decoders is meant to throw on bad input, so an
    // exception escaping one is a finding.
    e.fn(s);
    return 0;
}
