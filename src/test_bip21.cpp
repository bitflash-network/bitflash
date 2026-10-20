// Standalone tests for payment links (bip21.h).

#include "bip21.h"

#include <cstdio>
#include <string>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } } while(0)

static const char* ADDR = "BE39QRszEZSeqHnGEHqsZZV2hu5d8GCQAw";

int main()
{
    PaymentLink l;
    std::string err;

    printf("reading\n");
    CHECK(ParsePaymentLink(std::string("bitflash:") + ADDR, l, err) && l.address == ADDR && l.amount == 0,
          "an address alone");
    CHECK(ParsePaymentLink(std::string("bitflash:") + ADDR + "?amount=1.5&label=Coffee%20shop&message=two+cups", l, err) &&
          l.amount == 150000000 && l.label == "Coffee shop" && l.message == "two cups",
          "amount, label and message, decoded");
    CHECK(ParsePaymentLink(std::string("BITFLASH:") + ADDR + "?amount=0.00000001", l, err) && l.amount == 1,
          "the scheme in capitals (QR codes are often upper case), one satoshi");
    CHECK(ParsePaymentLink(std::string("bitflash://") + ADDR + "?amount=2", l, err) && l.address == ADDR && l.amount == 200000000,
          "bitflash:// as some apps write it");
    CHECK(ParsePaymentLink(std::string("bitflash:") + ADDR + "?foo=bar&amount=3", l, err) && l.amount == 300000000,
          "an optional parameter we do not know is ignored");
    CHECK(!ParsePaymentLink(std::string("bitflash:") + ADDR + "?req-escrow=1&amount=3", l, err) &&
          err.find("escrow") != std::string::npos,
          "a required one we do not know refuses the link");
    CHECK(!ParsePaymentLink(std::string("bitflash:") + ADDR + "?amount=1,5", l, err), "a comma is not a decimal point");
    CHECK(!ParsePaymentLink(std::string("bitflash:") + ADDR + "?amount=1e3", l, err), "no exponent");
    CHECK(!ParsePaymentLink(std::string("bitflash:") + ADDR + "?amount=-1", l, err), "no sign");
    CHECK(!ParsePaymentLink(std::string("bitflash:") + ADDR + "?amount=0.000000001", l, err), "no ninth decimal");
    CHECK(!ParsePaymentLink(std::string("bitflash:") + ADDR + "?amount=21000001", l, err), "no more than 21 million");
    CHECK(!ParsePaymentLink(std::string("bitflash:") + ADDR + "?label=%zz", l, err), "bad percent encoding");
    CHECK(!ParsePaymentLink(std::string("bitcoin:") + ADDR, l, err), "another coin's link is not ours");
    CHECK(!ParsePaymentLink("bitflash:?amount=1", l, err), "a link with no address");

    printf("writing\n");
    PaymentLink w;
    w.address = ADDR;
    w.amount = 150000000;
    w.label = "Café & co";
    std::string s = MakePaymentLink(w);
    CHECK(s == std::string("bitflash:") + ADDR + "?amount=1.5&label=Caf%C3%A9%20%26%20co", "amount trimmed, label encoded");
    CHECK(ParsePaymentLink(s, l, err) && l.amount == w.amount && l.label == w.label, "and it reads back");
    w.amount = 0;
    w.label.clear();
    CHECK(MakePaymentLink(w) == std::string("bitflash:") + ADDR, "an address alone writes as one");

    printf("\n%s (%d failures)\n", g_fail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", g_fail);
    return g_fail == 0 ? 0 : 1;
}
