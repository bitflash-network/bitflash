// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Bitflash hidden services -- self-certifying `.btf` addresses (a Tor `.onion`
// analogue, ported from the Itzal design). An address IS the service's public
// key: base32(pubkey[32] || checksum[2]).btf, derived from the owner's
// secp256k1 x-only key, so it cannot be forged (no CA, no DNS). Resolving it
// means proving a descriptor is signed by exactly this key.
//
// This is the ADDRESS + DESCRIPTOR layer. Reachability (rendezvous over the
// embedded Nostr relays so the origin IP is never exposed) builds on top.

#ifndef BITFLASH_BTFADDR_H
#define BITFLASH_BTFADDR_H

#include <string>
#include <vector>
#include <stdint.h>

namespace btf
{

// Pseudo-TLD, resolved inside the Bitflash client, never by real DNS.
extern const char* TLD; // ".btf"

// RFC 4648 base32, lowercase, no padding (case-insensitive hostname label).
std::string Base32Encode(const unsigned char* data, size_t n);
bool        Base32Decode(const std::string& s, std::vector<unsigned char>& out);

// Address versions.
//
// Version 1 is the original form -- key(32) || checksum(2), no version byte --
// and it is what Address() still emits. Every `.btf` in the wild is one and
// none of them change.
//
// From version 2 on the payload carries the version LAST, the way Tor v3 does
// it: key(32) || checksum(2) || version(1). That one byte is what lets the
// identity key stop being a secp256k1 x-only key some day -- a post-quantum
// signature scheme, say -- without retiring every address that exists, because
// old and new are told apart by length and both stay resolvable. Reserving it
// now costs nothing; needing it later without having reserved it costs a fork.
static const int ADDR_VERSION_XONLY = 1;

// Derive the `.btf` address for a 32-byte x-only public key (version 1).
std::string Address(const unsigned char pubkey[32]);

// Same, at an explicit version. Version 1 produces exactly what Address() does.
std::string AddressVersioned(const unsigned char pubkey[32], int nVersion);

// True if a hostname is a `.btf` address (case-insensitive, optional trailing dot).
bool IsBtf(const std::string& host);

// Parse a `.btf` address back to its 32-byte public key, verifying the checksum.
// Returns false if the label isn't valid base32, is the wrong length, or the
// checksum fails. Accepts any known version; use ParseAddressVersion when the
// caller has to act on which one it was.
bool ParseAddress(const std::string& addr, unsigned char pubkeyOut[32]);

// As above, and reports the version. A caller that cannot handle a version it
// does not know must refuse the address rather than treat it as version 1:
// two schemes answering to the same name is how an impostor gets in.
bool ParseAddressVersion(const std::string& addr, unsigned char pubkeyOut[32],
                         int& nVersionOut);


// ---- Service descriptor (published later on Nostr) -------------------------
//
// A descriptor tells a client how to REACH a service after resolving its
// address: "service <pubkey> is reachable via <meeting_node>, encrypt end-to-end
// to my x25519 key <enc>". It is signed by the service key and self-certifying:
// the client requires the signature to verify under the exact pubkey the
// address decodes to, so nobody can publish a descriptor for an address they
// don't own (no hijacking, even via a malicious relay).

struct Descriptor
{
    unsigned char pubkey[32];
    std::string   enc;          // service x25519 public key (hex) for the E2E channel
    std::string   meeting_node; // rendezvous node the service is registered at
    std::string   onion;        // optional direct Tor hidden-service endpoint (host.onion:port)
    uint64_t      created;
};

// Normalize and validate a direct Tor hidden-service endpoint. Only v3 onion
// names are accepted: 56 base32 chars plus ".onion", followed by ":PORT".
bool NormalizeOnionEndpoint(const std::string& in, std::string& out);

// Sign a descriptor. `ctx` is a secp256k1_context* (passed as void* to keep this
// header free of secp headers); `seckey` is the 32-byte service secret key.
// Returns the descriptor JSON as a string, or "" on failure.
std::string SignDescriptor(void* ctx, const unsigned char seckey[32],
                           const std::string& enc, const std::string& meeting_node,
                           uint64_t created,
                           const std::string& onion = std::string());

// Verify a descriptor is validly signed by `expect_pubkey` (the key the resolved
// `.btf` address encodes). Returns true and fills `out` on success.
bool VerifyDescriptor(void* ctx, const std::string& jsonStr,
                      const unsigned char expect_pubkey[32], Descriptor& out);

} // namespace btf

#endif
