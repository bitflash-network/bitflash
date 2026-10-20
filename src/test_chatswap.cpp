// Standalone tests for swaps arranged in the chat (chatswap.h): what an offer
// and each step must look like before the app acts on one.

#include "chatswap.h"

#include <cstdio>
#include <string>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } } while(0)

using namespace btfchat;

static const char* BTF_ADDR = "BE39QRszEZSeqHnGEHqsZZV2hu5d8GCQAw";
static const char* BTC_ADDR = "mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8";

int main()
{
    std::string err;

    printf("offers\n");
    {
        SwapOffer o;
        o.give = "BTF"; o.giveAmount = 100 * 100000000LL;
        o.want = "BTC"; o.wantAmount = 150000;
        o.note = "small first";
        SwapOffer back;
        CHECK(ParseSwapOffer(FormatSwapOffer(o), back, err) && back.give == "BTF" && back.want == "BTC" &&
              back.giveAmount == o.giveAmount && back.wantAmount == o.wantAmount && back.note == o.note,
              "an offer round-trips");
        CHECK(DescribeSwapOffer(o) == "100 BTF for 0.0015 BTC", "and reads as '100 BTF for 0.0015 BTC'");
        CHECK(!ParseSwapOffer("{\"give\":\"BTF\",\"ga\":1,\"want\":\"BTF\",\"wa\":1}", back, err),
              "BTF for BTF is not a swap");
        CHECK(!ParseSwapOffer("{\"give\":\"BTF\",\"ga\":1,\"want\":\"ETH\",\"wa\":1}", back, err),
              "a coin this build does not swap is refused");
        CHECK(!ParseSwapOffer("{\"give\":\"BTF\",\"ga\":0,\"want\":\"BTC\",\"wa\":1}", back, err),
              "nothing for something is refused");
        CHECK(!ParseSwapOffer("{\"give\":\"BTF\",\"ga\":2100000000000001,\"want\":\"BTC\",\"wa\":1}", back, err),
              "more than 21 million is refused");
        CHECK(!ParseSwapOffer("{\"give\":\"BTF\",\"ga\":1.5,\"want\":\"BTC\",\"wa\":1}", back, err),
              "an amount is whole satoshis, never a float");
        CHECK(!ParseSwapOffer("100 BTF for 0.0015 BTC", back, err), "free text is not an offer");
        o.note = std::string(MAX_SWAP_NOTE + 1, 'x');
        CHECK(!ParseSwapOffer(FormatSwapOffer(o), back, err), "a note past the limit is refused");
    }

    printf("steps\n");
    {
        SwapStep t;
        t.swap = std::string(32, 'a');
        t.step = "take";
        t.offer = std::string(32, 'b');
        t.terms.give = "BTF"; t.terms.giveAmount = 5; t.terms.want = "BTC"; t.terms.wantAmount = 7;
        t.to = BTF_ADDR;
        SwapStep back;
        CHECK(ParseSwapStep(FormatSwapStep(t), back, err) && back.step == "take" && back.offer == t.offer &&
              back.terms.giveAmount == 5 && back.to == BTF_ADDR, "a take round-trips");
        t.to = BTC_ADDR;
        CHECK(!ParseSwapStep(FormatSwapStep(t), back, err),
              "a take whose address is for the wrong coin is refused (paid in BTF, it needs a B address)");

        SwapStep l;
        l.swap = std::string(32, 'c');
        l.step = "lock1";
        l.chain = "BTC";
        l.contract = std::string(194, 'd');
        l.txid = std::string(64, 'e');
        l.vout = 1;
        l.to = BTF_ADDR;
        CHECK(ParseSwapStep(FormatSwapStep(l), back, err) && back.chain == "BTC" && back.vout == 1 && back.to == BTF_ADDR,
              "a lock on Bitcoin round-trips with its output");
        l.to = BTC_ADDR;
        CHECK(!ParseSwapStep(FormatSwapStep(l), back, err),
              "lock1 on Bitcoin wants to be paid in BTF, so its address must be a B address");
        l.to = BTF_ADDR;
        l.contract = std::string(302, 'd');
        CHECK(!ParseSwapStep(FormatSwapStep(l), back, err), "a contract past 150 bytes is refused");
        l.contract = "zz";
        CHECK(!ParseSwapStep(FormatSwapStep(l), back, err), "a contract that is not hex is refused");
        l.contract = std::string(194, 'd');
        l.txid = "abc";
        CHECK(!ParseSwapStep(FormatSwapStep(l), back, err), "a txid that is not 64 hex is refused");

        SwapStep l2;
        l2.swap = std::string(32, 'c');
        l2.step = "lock2";
        l2.chain = "BTF";
        l2.contract = std::string(194, 'd');
        l2.txid = std::string(64, 'e');
        CHECK(ParseSwapStep(FormatSwapStep(l2), back, err) && back.vout == -1,
              "a lock on Bitflash needs no output index");
        CHECK(!ParseSwapStep("{\"s\":\"cccccccccccccccccccccccccccccccc\",\"step\":\"lock2\",\"chain\":\"BTC\","
                             "\"c\":\"dd\",\"tx\":\"" + std::string(64, 'e') + "\"}", back, err),
              "a lock on Bitcoin without its output is refused");

        CHECK(!ParseSwapStep("{\"s\":\"short\",\"step\":\"cancel\"}", back, err), "a swap id is 32 hex");
        CHECK(!ParseSwapStep("{\"s\":\"" + std::string(32, 'a') + "\",\"step\":\"steal\"}", back, err),
              "an unknown step is refused");
        CHECK(ParseSwapStep("{\"s\":\"" + std::string(32, 'a') + "\",\"step\":\"cancel\",\"why\":\"changed my mind\"}", back, err) &&
              back.why == "changed my mind", "a cancel carries its reason");
    }

    printf("addresses\n");
    {
        CHECK(SwapAddressShapeOk("BTF", BTF_ADDR) && !SwapAddressShapeOk("BTF", BTC_ADDR), "a B address is BTF's");
        CHECK(SwapAddressShapeOk("BTC", BTC_ADDR) && SwapAddressShapeOk("BTC", "1111111111111111111114oLvT2") &&
              !SwapAddressShapeOk("BTC", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
              "a legacy key address is Bitcoin's; bc1 cannot be in the contract");
        CHECK(FormatSwapAmount(150000) == "0.0015" && FormatSwapAmount(100000000) == "1" &&
              FormatSwapAmount(1) == "0.00000001", "amounts print without trailing zeros");
    }

    printf("\n%s (%d failures)\n", g_fail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", g_fail);
    return g_fail == 0 ? 0 : 1;
}
