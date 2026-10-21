// Standalone tests for public communities (community.h): the listing format,
// names, the daily tag, and the seal on posts.

#include "community.h"

#include <sodium.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_fail = 0;
#define CHECK(cond, name) do { \
    if (cond) { printf("  ok   %s\n", name); } \
    else      { printf("  FAIL %s\n", name); g_fail++; } } while(0)

// OP_RETURN <data> the way a node's wallet writes it: 0x6a, then a direct push.
static std::vector<unsigned char> Script(const std::vector<unsigned char>& data)
{
    std::vector<unsigned char> s;
    s.push_back(0x6a);
    s.push_back((unsigned char)data.size());
    s.insert(s.end(), data.begin(), data.end());
    return s;
}

int main()
{
    if (sodium_init() < 0) { printf("libsodium failed to init\n"); return 1; }

    unsigned char key[32];
    randombytes_buf(key, sizeof(key));
    unsigned char back[32];
    std::string name;

    printf("a_listing_round_trips\n");
    {
        std::vector<unsigned char> d = community::ListingData(key, "bitflash");
        CHECK(d.size() == 38 + 8 && memcmp(&d[0], "BTFC", 4) == 0 && d[4] == 0 && d[5] == 4,
              "BTFC | 0 | 4 | key | name, the format tested on testnet in September");
        CHECK(community::ParseListing(Script(d), back, name) && name == "bitflash" &&
              memcmp(back, key, 32) == 0, "and reads back into the same key and name");
        std::vector<unsigned char> longest = community::ListingData(key, std::string(32, 'x'));
        CHECK(longest.size() == 70 && longest.size() <= 80, "the longest listing fits the relay limit");
    }

    printf("what_is_not_a_listing_is_not_read_as_one\n");
    {
        std::vector<unsigned char> d = community::ListingData(key, "ok");
        std::vector<unsigned char> s = Script(d);
        std::vector<unsigned char> t = s; t[2] = 'X';
        CHECK(!community::ParseListing(t, back, name), "wrong magic");
        t = s; t[2 + 4] = 1;
        CHECK(!community::ParseListing(t, back, name), "another version");
        t = s; t[2 + 5] = 3;
        CHECK(!community::ParseListing(t, back, name), "another purpose (a message stamp, say)");
        t = s; t[0] = 0x76;
        CHECK(!community::ParseListing(t, back, name), "not an OP_RETURN");
        t = s; t.push_back(0);
        CHECK(!community::ParseListing(t, back, name), "trailing bytes after the push");
        std::vector<unsigned char> noName(d.begin(), d.begin() + 38);
        CHECK(!community::ParseListing(Script(noName), back, name), "no name");
        std::vector<unsigned char> bad = community::ListingData(key, "a b");
        CHECK(!community::ParseListing(Script(bad), back, name), "a name with a space");
        std::vector<unsigned char> tooLong = community::ListingData(key, std::string(33, 'y'));
        CHECK(!community::ParseListing(Script(tooLong), back, name), "a name past 32 characters");
    }

    printf("names\n");
    {
        CHECK(community::NameOk("btf_chat-2"), "letters, digits, - and _");
        CHECK(!community::NameOk(""), "not empty");
        CHECK(!community::NameOk("ação"), "ASCII only: two names that look the same must be the same bytes");
        CHECK(!community::NameOk("#btf"), "no #, which the window adds");
    }

    printf("the_id_and_the_daily_tag\n");
    {
        std::string id = community::IdHex(key);
        CHECK(id.size() == 64 && id == community::IdHex(key), "the id is stable and 32 bytes of hex");
        unsigned char other[32];
        memcpy(other, key, 32);
        other[0] ^= 1;
        CHECK(community::IdHex(other) != id, "and another key has another id");
        std::string t1 = community::TagHex(key, 20000), t2 = community::TagHex(key, 20001);
        CHECK(t1.size() == 32 && t1 == community::TagHex(key, 20000), "a tag is 16 bytes, the same for everyone that day");
        CHECK(t1 != t2, "and different the next day");
        CHECK(t1.compare(0, 32, id, 0, 32) != 0, "and is not the id");
    }

    printf("posts_are_sealed_with_the_key\n");
    {
        std::string post = "{\"k\":4,\"text\":\"ola\"}";
        std::vector<unsigned char> env;
        CHECK(community::Seal(key, post, env), "a post seals");
        std::string got;
        CHECK(community::Open(key, env, got) && got == post, "and opens with the key");
        unsigned char other[32];
        randombytes_buf(other, 32);
        CHECK(!community::Open(other, env, got), "but not with another community's key");
        env[env.size() - 1] ^= 1;
        CHECK(!community::Open(key, env, got), "and not once a byte has changed");
        std::vector<unsigned char> tiny(5, 0);
        CHECK(!community::Open(key, tiny, got), "nor from a stub");
    }

    printf("\n%s (%d failures)\n", g_fail == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", g_fail);
    return g_fail == 0 ? 0 : 1;
}
