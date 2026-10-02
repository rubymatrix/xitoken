using System.Text;
using System.Text.Json.Nodes;
using Xunit;

namespace XiToken.Tests;

public class FixedClock(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;
    public override DateTimeOffset GetUtcNow() => Now;
}

public class VectorTests
{
    private static JsonObject Load(string name) =>
        JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors", name)))!.AsObject();

    private static byte[] Hex(string hex) => Convert.FromHexString(hex);

    private static DateTimeOffset VectorNow(JsonObject doc)
    {
        Assert.True(Rfc3339.TryParse((string)doc["now"]!, out DateTimeOffset now));
        return now;
    }

    public static TheoryData<string> PasetoNames() => [.. Load("paseto-v4-public.json")["tests"]!.AsArray().Select(t => (string)t!["name"]!)];

    [Theory]
    [MemberData(nameof(PasetoNames))]
    public void UpstreamPasetoVectors(string name)
    {
        JsonObject t = Load("paseto-v4-public.json")["tests"]!.AsArray().Single(x => (string)x!["name"]! == name)!.AsObject();
        if (t["public-key"] is null)
        {
            // key-misuse vector (a v4.local key offered for a v4.public token): there is no public key to verify with
            Assert.True((bool)t["expect-fail"]!);
            Assert.False(Paseto.Verify((string)t["token"]!, Hex((string)t["key"]!), out _, out _));
            return;
        }
        byte[] pub = Hex((string)t["public-key"]!);
        byte[] implicitAssertion = Encoding.UTF8.GetBytes((string)t["implicit-assertion"]!);
        string token = (string)t["token"]!;

        bool ok = Paseto.Verify(token, pub, out byte[] payload, out byte[] footer, implicitAssertion);
        if ((bool)t["expect-fail"]!)
        {
            Assert.False(ok);
            return;
        }
        Assert.True(ok);
        Assert.Equal((string)t["payload"]!, Encoding.UTF8.GetString(payload));
        Assert.Equal((string)t["footer"]!, Encoding.UTF8.GetString(footer));

        var key = SigningKey.FromSeed("upstream", Hex((string)t["secret-key-seed"]!));
        Assert.Equal(pub, key.PublicKey);
        Assert.Equal(token, Paseto.Sign(key, payload, footer, implicitAssertion));
    }

    [Fact]
    public void ServerIds()
    {
        foreach (JsonNode? v in Load("xitoken.json")["server_ids"]!.AsArray())
        {
            byte[] pub = Paserk.Decode((string)v!["public"]!, Paserk.PublicPrefix, 32);
            string id = ServerId.FromPublicKey(pub);
            Assert.Equal((string)v["server_id"]!, id);
            Assert.True(ServerId.IsValid(id));
        }
    }

    public static TheoryData<string> KeysetNames() => [.. Load("xitoken.json")["keyset_cases"]!.AsArray().Select(c => (string)c!["name"]!)];

    [Theory]
    [MemberData(nameof(KeysetNames))]
    public void KeysetVectors(string name)
    {
        JsonObject doc = Load("xitoken.json");
        JsonObject c = doc["keyset_cases"]!.AsArray().Single(x => (string)x!["name"]! == name)!.AsObject();
        var resolver = new KeySetResolver();
        bool ok;
        try
        {
            resolver.Trust((string)c["token"]!, (string)c["trust"]!, VectorNow(doc));
            ok = true;
        }
        catch (FormatException)
        {
            ok = false;
        }
        Assert.Equal((string)c["expect"]! == "ok", ok);
    }

    public static TheoryData<string> XiNames() => [.. Load("xitoken.json")["cases"]!.AsArray().Select(c => (string)c!["name"]!)];

    [Theory]
    [MemberData(nameof(XiNames))]
    public void TokenVectors(string name)
    {
        JsonObject doc = Load("xitoken.json");
        JsonObject c = doc["cases"]!.AsArray().Single(x => (string)x!["name"]! == name)!.AsObject();
        string token = (string)c["token"]!;

        if ((bool)c["resign"]!)
        {
            var key = SigningKey.FromPaserk("2026-10", (string)doc["signing_secret"]!);
            Assert.Equal(token, Paseto.Sign(key, Encoding.UTF8.GetBytes((string)c["payload"]!), Encoding.UTF8.GetBytes((string)c["footer"]!)));
        }

        DateTimeOffset now = VectorNow(doc);
        var resolver = new KeySetResolver();
        foreach (JsonNode? ks in doc["trusted_keysets"]!.AsArray())
            resolver.Trust((string)ks!["token"]!, (string)ks["server_id"]!, now);
        var clock = new FixedClock(now);
        var verifier = new TokenVerifier(resolver, new VerifierOptions
        {
            Audience = (string)doc["audience"]!,
            ClockSkew = TimeSpan.FromSeconds((int)doc["clock_skew_seconds"]!),
            MaxLifetime = TimeSpan.FromSeconds((int)doc["max_lifetime_seconds"]!),
            ReplayGuard = new MemoryReplayGuard(clock),
            Clock = clock,
        });

        VerifyResult result = default;
        int repeat = c["repeat"] is JsonNode r ? (int)r : 1;
        for (int i = 0; i < repeat; i++)
            result = verifier.Verify(token, (string)c["type"]!);

        Assert.Equal((string)c["expect"]!, result.Error.Name());
        if (c["world_entry_valid"] is JsonNode we)
            Assert.Equal((bool)we, WorldEntry.FromClaims(result.Token!.Claims) is not null);
    }
}

public class RoundTripTests
{
    [Fact]
    public void IssueThenVerifyWorldEntry()
    {
        var clock = new FixedClock(DateTimeOffset.UtcNow);
        SigningKey identity = SigningKey.Generate("identity");
        SigningKey signing = SigningKey.Generate("2026-10");
        string world = SigningKey.Generate("identity").ServerId;

        var resolver = new KeySetResolver();
        resolver.Trust(KeySet.Create(identity, "Crystal", [signing], clock.Now), identity.ServerId, clock.Now);

        var entry = new WorldEntry(4097, "Ayame", "10.0.0.7", "20100904_2", 30, Enumerable.Range(0, 20).Select(i => (byte)i).ToArray());
        string token = new TokenIssuer(identity.ServerId, signing, clock).Issue(WorldEntry.Type, world, "polid-1", WorldEntry.DefaultLifetime, entry.ToClaims());

        var verifier = new TokenVerifier(resolver, new VerifierOptions { Audience = world, ReplayGuard = new MemoryReplayGuard(clock), Clock = clock });
        VerifyResult result = verifier.Verify(token, WorldEntry.Type);
        Assert.True(result.Ok, result.Error.ToString());
        Assert.Equal($"{identity.ServerId}:polid-1", result.Token!.PlayerId);

        WorldEntry? back = WorldEntry.FromClaims(result.Token.Claims);
        Assert.NotNull(back);
        Assert.Equal(entry.SessionKey, back.SessionKey);
        Assert.Equal(entry with { SessionKey = back.SessionKey }, back);
        Assert.DoesNotContain("0001020304", back.ToString());

        Assert.Equal(TokenError.Replayed, verifier.Verify(token, WorldEntry.Type).Error);
        clock.Now += TimeSpan.FromMinutes(2);
        Assert.Equal(TokenError.Expired, verifier.Verify(token, WorldEntry.Type).Error);
    }

    [Fact]
    public void RotationReplacesKeysAndRefusesRollback()
    {
        DateTimeOffset t0 = DateTimeOffset.UtcNow;
        SigningKey identity = SigningKey.Generate("identity");
        SigningKey oldKey = SigningKey.Generate("old"), newKey = SigningKey.Generate("new");
        string v1 = KeySet.Create(identity, null, [oldKey], t0);
        string v2 = KeySet.Create(identity, null, [newKey], t0.AddHours(1));

        var resolver = new KeySetResolver();
        resolver.Trust(v1, identity.ServerId, t0);
        resolver.Trust(v2, identity.ServerId, t0);
        Assert.Null(resolver.Find(identity.ServerId, "old"));
        Assert.NotNull(resolver.Find(identity.ServerId, "new"));
        Assert.Throws<FormatException>(() => resolver.Trust(v1, identity.ServerId, t0));
    }

    [Fact]
    public void PaserkRoundTrip()
    {
        SigningKey key = SigningKey.Generate("k");
        SigningKey back = SigningKey.FromPaserk("k", key.ToPaserk());
        Assert.Equal(key.Seed, back.Seed);
        Assert.Throws<FormatException>(() => SigningKey.FromPaserk("k", key.PublicPaserk));
    }

    [Theory]
    [InlineData("A")]
    [InlineData("AB")] // non-canonical: trailing bits set
    [InlineData("AA==")]
    [InlineData("A+B/")]
    [InlineData("AA AA")]
    public void Base64UrlRejects(string text) => Assert.False(Base64Url.TryDecode(text, out _));
}
