// Runs vectors/paseto-v4-public.json and vectors/xitoken.json against the C++ implementation, plus a round trip.
#include "xitoken/xitoken.h"

#include <cstdio>
#include <fstream>
#include <sstream>

using nlohmann::json;
using namespace xitoken;

namespace
{
    int failures = 0;
    int checks   = 0;

    void check(bool ok, const std::string& what)
    {
        ++checks;
        if (!ok)
        {
            ++failures;
            std::printf("FAIL %s\n", what.c_str());
        }
    }

    auto load(const std::string& name) -> json
    {
        std::ifstream     file(std::string(XITOKEN_VECTORS_DIR) + "/" + name, std::ios::binary);
        std::stringstream ss;
        ss << file.rdbuf();
        return json::parse(ss.str());
    }

    auto hex(const std::string& text) -> Bytes
    {
        Bytes out;
        for (size_t i = 0; i + 1 < text.size(); i += 2)
        {
            out.push_back(static_cast<uint8_t>(std::stoi(text.substr(i, 2), nullptr, 16)));
        }
        return out;
    }

    auto key32(const Bytes& b) -> Key32
    {
        Key32 k{};
        std::copy_n(b.begin(), std::min<size_t>(32, b.size()), k.begin());
        return k;
    }

    void upstreamVectors()
    {
        for (const auto& t : load("paseto-v4-public.json")["tests"])
        {
            std::string name  = t["name"];
            std::string token = t["token"];
            bool        fail  = t["expect-fail"];
            std::string ia    = t["implicit-assertion"];
            if (!t.contains("public-key"))
            {
                // key-misuse vector: a v4.local key offered for a v4.public token
                check(fail && !paseto::verify(token, key32(hex(t["key"])), ia), name);
                continue;
            }
            auto parts = paseto::verify(token, key32(hex(t["public-key"])), ia);
            if (fail)
            {
                check(!parts, name);
                continue;
            }
            check(parts && parts->payload == t["payload"].get<std::string>() && parts->footer == t["footer"].get<std::string>(), name + " verify");

            auto key = SigningKey::fromSeed("upstream", key32(hex(t["secret-key-seed"])));
            check(key && key->publicKey() == key32(hex(t["public-key"])), name + " public key");
            check(key && paseto::sign(*key, t["payload"].get<std::string>(), t["footer"].get<std::string>(), ia) == token, name + " sign");
        }
    }

    void serverIds()
    {
        for (const auto& v : load("xitoken.json")["server_ids"])
        {
            auto pub = decodePaserkPublic(v["public"].get<std::string>());
            check(pub && serverIdFromPublicKey(*pub) == v["server_id"].get<std::string>() && isValidServerId(v["server_id"].get<std::string>()),
                  "server id " + v["server_id"].get<std::string>());
        }
    }

    void keysetVectors()
    {
        json    doc = load("xitoken.json");
        int64_t now = *rfc3339::parse(doc["now"].get<std::string>());
        for (const auto& c : doc["keyset_cases"])
        {
            KeySetResolver resolver;
            bool           ok = resolver.trust(c["token"].get<std::string>(), c["trust"].get<std::string>(), now);
            check(ok == (c["expect"] == "ok"), "keyset: " + c["name"].get<std::string>());
        }
    }

    void tokenVectors()
    {
        json doc = load("xitoken.json");
        auto key = SigningKey::fromPaserk("2026-10", doc["signing_secret"].get<std::string>());
        check(key.has_value(), "signing key decodes");

        int64_t        now = *rfc3339::parse(doc["now"].get<std::string>());
        KeySetResolver resolver;
        for (const auto& ks : doc["trusted_keysets"])
        {
            std::string error;
            check(resolver.trust(ks["token"].get<std::string>(), ks["server_id"].get<std::string>(), now, &error), "trusted keyset " + error);
        }

        for (const auto& c : doc["cases"])
        {
            std::string name  = c["name"];
            std::string token = c["token"];
            if (c["resign"].get<bool>())
            {
                check(key && paseto::sign(*key, c["payload"].get<std::string>(), c["footer"].get<std::string>()) == token, name + " sign");
            }

            MemoryReplayGuard guard([&] { return now; });
            VerifierOptions   options;
            options.audience    = doc["audience"];
            options.clockSkew   = doc["clock_skew_seconds"];
            options.maxLifetime = doc["max_lifetime_seconds"];
            options.replayGuard = &guard;
            options.now         = [&] { return now; };
            Verifier verifier(resolver, options);

            VerifyResult result;
            int          repeat = c.value("repeat", 1);
            for (int i = 0; i < repeat; ++i)
            {
                result = verifier.verify(token, c["type"].get<std::string>());
            }
            std::string got = toString(result.error);
            check(got == c["expect"].get<std::string>(), name + ": expected " + c["expect"].get<std::string>() + ", got " + got);
            if (c.contains("world_entry_valid"))
            {
                check(result.token && WorldEntry::fromClaims(result.token->claims).has_value() == c["world_entry_valid"].get<bool>(),
                      name + " world entry");
            }
        }
    }

    void roundTrip()
    {
        int64_t now      = systemNow();
        auto    identity = SigningKey::generate("identity");
        auto    signing  = SigningKey::generate("2026-10");
        auto    world    = SigningKey::generate("identity")->serverId();
        check(identity && signing, "generate");
        auto again = SigningKey::fromPaserk("2026-10", signing->paserkSecret());
        check(again && again->seed() == signing->seed(), "paserk round trip");

        KeySetResolver resolver;
        std::string    error;
        check(resolver.trust(KeySet::create(*identity, std::string("Crystal"), { *signing }, now), identity->serverId(), now, &error),
              "trust own keyset " + error);
        check(!resolver.trust(KeySet::create(*identity, std::nullopt, { *signing }, now - 10), identity->serverId(), now), "older keyset refused");

        WorldEntry entry;
        entry.charId           = 4097;
        entry.charName         = "Ayame";
        entry.clientIp         = "10.0.0.7";
        entry.clientVersion    = "20100904_2";
        entry.clientExpansions = 30;
        for (size_t i = 0; i < entry.sessionKey.size(); ++i)
        {
            entry.sessionKey[i] = static_cast<uint8_t>(i);
        }
        std::string token = Issuer(identity->serverId(), *signing)
                                .issue(std::string(WorldEntry::type), world, "polid-1", WorldEntry::defaultLifetime, entry.toClaims(), now);

        MemoryReplayGuard guard([&] { return now; });
        VerifierOptions   options;
        options.audience    = world;
        options.replayGuard = &guard;
        options.now         = [&] { return now; };
        Verifier verifier(resolver, options);

        auto result = verifier.verify(token, WorldEntry::type);
        check(static_cast<bool>(result), std::string("round trip verify: ") + toString(result.error));
        check(result.token && result.token->playerId() == identity->serverId() + ":polid-1", "player id");
        auto back = result.token ? WorldEntry::fromClaims(result.token->claims) : std::nullopt;
        check(back && back->sessionKey == entry.sessionKey && back->charId == 4097 && back->charName == entry.charName, "world entry back");
        check(back && back->clientAddrLsb() == (10u | 7u << 24), "client addr");
        check(verifier.verify(token, WorldEntry::type).error == Error::Replayed, "replayed");
        now += 120;
        check(verifier.verify(token, WorldEntry::type).error == Error::Expired, "expired");

        check(!base64url::decode("AB"), "non-canonical base64");
        check(!base64url::decode("AA=="), "padded base64");
        check(rfc3339::format(0) == "1970-01-01T00:00:00Z", "format epoch");
        check(rfc3339::parse("2024-02-29T00:00:00Z").has_value() && !rfc3339::parse("2023-02-29T00:00:00Z"), "leap day");
    }
} // namespace

int main()
{
    upstreamVectors();
    serverIds();
    keysetVectors();
    tokenVectors();
    roundTrip();
    std::printf("%d/%d checks passed\n", checks - failures, checks);
    return failures == 0 ? 0 : 1;
}
