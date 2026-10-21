// Copyright (c) 2026 Bitflash developers
// Distributed under the MIT/X11 software license.
//
// Invoices: a payment gateway that is only the shop's own node.
//
// A shop asks its node for an invoice -- an amount, what it is for, how long
// it stays open -- and gets back a fresh address of its own wallet, the
// payment link (bitflash:..., what the customer copies and pastes) and its QR
// code as SVG, ready for the checkout page. The node watches its own wallet
// for the payment and tells the shop when the invoice changes: a POST to the
// shop's own URL, signed with a secret the two share, and/or a command run on
// the machine. There is no gateway company, no server of ours, no account:
// the money goes straight into the shop's wallet, and the only thing that
// knows about the sale is the shop's node.
//
// STATUS
//   waiting   nothing has arrived yet
//   partial   something has, less than the amount
//   seen      the whole amount is in transactions not yet confirmed enough.
//             NOT money yet: until it is in blocks a payer can replace a
//             payment (BIP125) or double-spend it. Show "payment received,
//             confirming" -- never ship on it.
//   paid      the whole amount, with the confirmations asked for
//             (-invoiceminconf; 2 on mainnet, 1 on testnet). This is money.
//   expired   the invoice ran out before the amount arrived. A payment that
//             comes later is still received, and still reported.
//   cancelled the shop cancelled it
// Anything over the amount is reported as `overpaid`.

#ifndef BITFLASH_INVOICE_H
#define BITFLASH_INVOICE_H

#include "rpcclient.h"

#include <string>
#include <vector>
#include <stdint.h>

namespace invoice
{

struct Config
{
    std::string strWebhookUrl;      // http://host[:port]/path
    std::string strWebhookSecret;   // HMAC-SHA256 key for X-Bitflash-Signature
    std::string strNotifyCommand;   // run with %s replaced by the invoice id
    int nMinConf = 0;               // 0: 2 on mainnet, 1 on testnet
};

// From the flags. errOut when the webhook URL is not one this can call.
bool Configure(const Config& cfg, std::string& errOut);

// The RPCs. They throw std::runtime_error with a message for the caller.
nlohmann::json Create(int64_t nAmount, const std::string& strDescription, int64_t nExpirySecs,
                      const std::string& strOrderId);
nlohmann::json Get(const std::string& id);
nlohmann::json List(const std::string& strStatusFilter);
nlohmann::json Cancel(const std::string& id);

// Watches the wallet and sends the notifications; started with the RPC server.
void ThreadInvoices(void* parg);

// ---- pure, for the self-test ----

std::string StatusFor(int64_t nAmount, int64_t nReceived, int64_t nReceivedConfirmed,
                      bool fCancelled, int64_t nExpires, int64_t nNow);
// The QR code of a text as an SVG document, dark on white with the quiet zone.
std::string QrSvg(const std::string& text);
// HMAC-SHA256 of body under secret, lowercase hex.
std::string SignBody(const std::string& secret, const std::string& body);
// http://host[:port]/path, or false.
bool ParseHttpUrl(const std::string& url, std::string& hostOut, unsigned short& portOut,
                  std::string& pathOut);

} // namespace invoice

#endif
