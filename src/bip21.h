// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Payment links (BIP21, with the bitflash: scheme):
//
//     bitflash:BE39QRszEZSeqHnGEHqsZZV2hu5d8GCQAw?amount=1.5&label=Coffee
//
// What a QR code on a shop counter holds, and what a phone scans to pay. The
// amount is in BTF, as BIP21's is in BTC. A parameter starting with "req-"
// is one the payer must understand: a link carrying one we do not is refused,
// as BIP21 says, rather than paid without whatever it required.
//
// Pure: no wallet, no network.

#ifndef BITFLASH_BIP21_H
#define BITFLASH_BIP21_H

#include <string>
#include <stdint.h>

struct PaymentLink
{
    std::string address;
    int64_t     amount = 0;     // satoshis; 0 when the link names none
    std::string label;          // who is being paid
    std::string message;        // what for
};

bool ParsePaymentLink(const std::string& uri, PaymentLink& out, std::string& errOut);
std::string MakePaymentLink(const PaymentLink& link);

#endif
