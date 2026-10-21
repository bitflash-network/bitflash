// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Bitflash end-to-end encrypted channel.
//
// HANDSHAKE -- hybrid, three flights. The session key is derived from three
// secrets at once, and an attacker has to break every one of them:
//
//   X25519(ephemeral, ephemeral)  forward secrecy against a stolen long-term key
//   X25519(ephemeral, static)     proves the endpoint is the one its .btf names
//   ML-KEM-1024 (ephemeral)       forward secrecy against a quantum computer
//
// The classical halves come from libsodium, the post-quantum half from
// mlkem-native (vendored under mlkem/). They are MIXED, never chosen between:
// if X25519 falls, ML-KEM still holds; if ML-KEM falls, X25519 still holds.
//
// What the old version did, and why this replaced it: the shared key was
// X25519(client ephemeral, endpoint STATIC). One side was fixed, so anyone who
// recorded traffic and later stole that one key decrypted everything they had
// kept. Both sides are ephemeral now, and the static key only authenticates.
//
// Authentication stays classical on purpose. Forging a signature needs the
// quantum computer at the moment of the handshake; decrypting a recording needs
// it merely some day. Confidentiality is the half that cannot wait, so that is
// the half that got the post-quantum treatment first. The .btf address carries
// a version byte so the identity key can change scheme later without a fork.
//
// FRAMES -- every frame is sealed under its own key, taken from a chain that
// ratchets forward and cannot be rewound. A key lifted out of a live process
// opens the frame it belongs to, not the conversation behind it. The counter is
// authenticated, so frames cannot be reordered, dropped or replayed silently.
//
//   wire: [len:4 BE][counter:8 BE][ciphertext || 16-byte tag]

#ifndef BITFLASH_BTFCHAN_H
#define BITFLASH_BTFCHAN_H

#include <vector>
#include <stdint.h>
#include <stddef.h>

namespace btf
{

static const int CHAN_KEYBYTES   = 32; // X25519 keys, chain keys, message keys
static const int CHAN_NONCEBYTES = 24; // XChaCha20-Poly1305 nonce
static const int CHAN_MACBYTES   = 16; // Poly1305 tag
static const int CHAN_CTRBYTES   = 8;  // frame counter, big endian

// ML-KEM-1024 sizes. Checked against the library's own macros in btfchan.cpp,
// so a parameter-set mistake is a compile error and not a runtime surprise.
//
// 1024 rather than the 768 that Signal and TLS settled on: the two extra flights
// cost 864 bytes once per connection, which is two Tor cells on a handshake that
// already spends seconds on round trips. Since the classical and post-quantum
// secrets are mixed, an attacker has to break both -- so against a quantum one,
// where X25519 is the half that falls, what is left standing is this number.
static const int CHAN_KEM_PUBBYTES = 1568;
static const int CHAN_KEM_SECBYTES = 3168;
static const int CHAN_KEM_CTBYTES  = 1568;

// What each flight puts on the wire.
static const int CHAN_HS1BYTES = CHAN_KEYBYTES;                       // client -> endpoint
static const int CHAN_HS2BYTES = CHAN_KEYBYTES + CHAN_KEM_PUBBYTES;   // endpoint -> client
static const int CHAN_HS3BYTES = CHAN_KEM_CTBYTES;                    // client -> endpoint

// Must be called once before any channel use (initializes libsodium). Idempotent.
bool ChanInit();

// Generate a static X25519 keypair (the endpoint's long-term identity).
void ChanKeypair(unsigned char pk[CHAN_KEYBYTES], unsigned char sk[CHAN_KEYBYTES]);

// Derive the X25519 public key from a stored secret key.
void ChanPublicFromSecret(unsigned char pk[CHAN_KEYBYTES], const unsigned char sk[CHAN_KEYBYTES]);

// A live channel: one ratchet per direction, and the counter each one is at.
// Zeroed by ChanSessionClear() when the connection ends.
struct ChanSession
{
    unsigned char ck_send[CHAN_KEYBYTES];
    unsigned char ck_recv[CHAN_KEYBYTES];
    uint64_t      n_send;
    uint64_t      n_recv;
};

// Handshake state each side keeps between flights. Both hold secret key
// material: clear them with the matching Clear() as soon as the handshake ends,
// success or failure.
struct ChanClientCtx
{
    unsigned char eph_sk[CHAN_KEYBYTES];
    unsigned char eph_pub[CHAN_KEYBYTES];
};

struct ChanEndpointCtx
{
    unsigned char eph_sk[CHAN_KEYBYTES];
    unsigned char eph_pub[CHAN_KEYBYTES];
    unsigned char kem_sk[CHAN_KEM_SECBYTES];
    unsigned char kem_pub[CHAN_KEM_PUBBYTES];
    unsigned char client_eph_pub[CHAN_KEYBYTES];
};

void ChanClientCtxClear(ChanClientCtx& ctx);
void ChanEndpointCtxClear(ChanEndpointCtx& ctx);
void ChanSessionClear(ChanSession& s);

// Flight 1, client: fresh X25519 ephemeral out, secret kept in ctx.
bool ChanClientFlight1(ChanClientCtx& ctx, unsigned char out[CHAN_HS1BYTES]);

// Flight 2, endpoint: fresh X25519 ephemeral and a fresh ML-KEM keypair out.
// The ML-KEM keypair is per-connection, which is what buys post-quantum forward
// secrecy -- a long-term KEM key would leave recordings open to whoever steals
// it later, the very hole this handshake exists to close.
bool ChanEndpointFlight2(ChanEndpointCtx& ctx,
                         const unsigned char hs1[CHAN_HS1BYTES],
                         unsigned char out[CHAN_HS2BYTES]);

// Flight 3, client: encapsulates to the endpoint's ML-KEM key, mixes the three
// secrets, and comes out with a live session. endpoint_static_pub is the key the
// .btf address names -- the only thing that stops a relay from sitting in the
// middle, so a caller that passes an unverified key has no authentication at all.
bool ChanClientFlight3(ChanClientCtx& ctx,
                       const unsigned char endpoint_static_pub[CHAN_KEYBYTES],
                       const unsigned char hs2[CHAN_HS2BYTES],
                       unsigned char out[CHAN_HS3BYTES],
                       ChanSession& sess);

// Endpoint, after flight 3: same three secrets from the other side.
bool ChanEndpointFinish(ChanEndpointCtx& ctx,
                        const unsigned char my_static_sk[CHAN_KEYBYTES],
                        const unsigned char hs3[CHAN_HS3BYTES],
                        ChanSession& sess);

// Seal one frame and advance the send ratchet. Returns the whole wire frame.
std::vector<unsigned char> ChanEncryptFrame(ChanSession& sess,
                                            const unsigned char* pt, size_t n);

// Open one frame body (everything after the 4-byte length) and advance the recv
// ratchet. Fails on a bad tag, a short body, or a counter that is not the one
// expected next -- out is left empty and the ratchet does not move.
bool ChanDecryptBody(ChanSession& sess,
                     const unsigned char* body, size_t n,
                     std::vector<unsigned char>& out);

// ---- store and forward -----------------------------------------------------
//
// Everything above needs both sides online at once. A message left for someone
// who is not there cannot use it, and that message is the one in the most
// danger: it sits somewhere that is not ours, where anyone may copy it and keep
// it. Harvest now, decrypt later is not a worry here, it is the default
// assumption, which is why this path is hybrid too and not a classical
// sealed box.
//
// ANONYMOUS. The envelope names no sender. Who wrote it is inside, signed, for
// the recipient alone -- whoever holds the envelope learns nothing from it.
//
// FORWARD SECRECY comes from ROTATION, not from an ephemeral on the receiving
// side: there is nobody there to make one. The recipient publishes both of the
// public keys below per epoch, signs them with its chat identity, and destroys
// the secrets when the epoch passes. Envelopes older than that cannot be opened
// by anyone, including the recipient. Feeding this a long-term key instead works
// and quietly gives up that property, so callers pass epoch keys.
static const int CHAN_SEAL_OVERHEAD = CHAN_KEYBYTES + CHAN_KEM_CTBYTES + CHAN_MACBYTES;

// A fresh ML-KEM keypair for one epoch's mailbox.
bool ChanKemKeypair(unsigned char pk[CHAN_KEM_PUBBYTES], unsigned char sk[CHAN_KEM_SECBYTES]);

// Seal to a recipient's epoch keys. Needs BOTH: the X25519 half and the ML-KEM
// half are mixed, so an attacker has to break both, exactly as in the live
// handshake. Both public keys go into the derivation, so an envelope cannot be
// re-aimed at a different recipient.
bool ChanSealTo(const unsigned char recip_x25519_pub[CHAN_KEYBYTES],
                const unsigned char recip_kem_pub[CHAN_KEM_PUBBYTES],
                const unsigned char* pt, size_t n,
                std::vector<unsigned char>& out);

// Open one. Fails on a short envelope, a bad tag, or the wrong pair of secrets
// -- which is also what an envelope from an expired epoch looks like.
// The recipient's own public keys are part of the derivation, so they are passed
// in rather than dug out of the secret key: ML-KEM secret keys do carry their
// public half, and depending on where would make a library's internal change our
// silent breakage.
bool ChanOpenSealed(const unsigned char recip_x25519_sk[CHAN_KEYBYTES],
                    const unsigned char recip_kem_pub[CHAN_KEM_PUBBYTES],
                    const unsigned char recip_kem_sk[CHAN_KEM_SECBYTES],
                    const unsigned char* in, size_t n,
                    std::vector<unsigned char>& out);

} // namespace btf

#endif
