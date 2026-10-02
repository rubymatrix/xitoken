using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using XiToken;

// xitoken-cli: operator tool for identities, key sets and tokens. Secret keys are files holding one k4.secret line.
return Run(args);

static int Run(string[] args)
{
    if (args.Length == 0)
        return Usage();
    var opts = ParseOptions(args[1..], out List<string> positional);
    try
    {
        switch (args[0])
        {
            case "keygen":
            {
                string kid = opts.GetValueOrDefault("kid", "identity");
                SigningKey key = SigningKey.Generate(kid);
                string path = Need(opts, "out");
                if (File.Exists(path))
                    throw new UsageException($"{path} exists; refusing to overwrite a key");
                File.WriteAllText(path, key.ToPaserk() + "\n");
                Console.WriteLine($"wrote     {path}");
                Console.WriteLine($"public    {key.PublicPaserk}");
                Console.WriteLine($"server id {key.ServerId}   (if this is used as an identity key)");
                return 0;
            }
            case "keyset":
            {
                // xitoken-cli keyset --identity id.key [--name Crystal] [--days 365] 2026-10=signing.key ...
                SigningKey identity = LoadKey("identity", Need(opts, "identity"));
                var keys = positional.Select(p => p.Split('=', 2)).Select(kv => kv.Length == 2
                    ? LoadKey(kv[0], kv[1])
                    : throw new UsageException("signing keys are given as <kid>=<secret key file>")).ToList();
                DateTimeOffset now = DateTimeOffset.UtcNow;
                DateTimeOffset? exp = opts.TryGetValue("days", out string? days) ? now.AddDays(int.Parse(days)) : null;
                Console.WriteLine(KeySet.Create(identity, opts.GetValueOrDefault("name"), keys, now, exp));
                return 0;
            }
            case "show-keyset":
            {
                if (positional.Count != 1)
                    throw new UsageException("show-keyset takes one file");
                KeySet set = KeySet.Open(File.ReadAllText(positional[0]), DateTimeOffset.UtcNow);
                Console.WriteLine($"server id {set.ServerId}");
                Console.WriteLine($"name      {set.Name ?? "(none)"}");
                Console.WriteLine($"issued    {Rfc3339.Format(set.IssuedAt)}");
                Console.WriteLine($"expires   {(set.Expires is { } e ? Rfc3339.Format(e) : "never")}");
                foreach (TrustedKey key in set.Keys)
                    Console.WriteLine($"key       {key.KeyId}  {Paserk.PublicPrefix}{Base64Url.Encode(key.PublicKey)}");
                return 0;
            }
            case "issue":
            {
                SigningKey key = LoadKey(Need(opts, "kid"), Need(opts, "key"));
                var issuer = new TokenIssuer(Need(opts, "issuer"), key);
                JsonObject? claims = opts.TryGetValue("claims", out string? c)
                    ? JsonNode.Parse(c) as JsonObject ?? throw new UsageException("--claims must be a JSON object")
                    : null;
                int seconds = int.Parse(opts.GetValueOrDefault("lifetime", "60"));
                Console.WriteLine(issuer.Issue(Need(opts, "type"), Need(opts, "aud"), Need(opts, "sub"), TimeSpan.FromSeconds(seconds), claims));
                return 0;
            }
            case "verify":
            {
                if (positional.Count != 1)
                    throw new UsageException("verify takes one token");
                var resolver = new KeySetResolver();
                foreach (string trust in Need(opts, "trust").Split(','))
                {
                    string[] kv = trust.Split('=', 2);
                    if (kv.Length != 2)
                        throw new UsageException("--trust takes <server id>=<key set file>[,...]");
                    resolver.TrustFile(kv[1], kv[0]);
                }
                var verifier = new TokenVerifier(resolver, new VerifierOptions { Audience = Need(opts, "aud") });
                VerifyResult result = verifier.Verify(positional[0], Need(opts, "type"));
                if (!result.Ok)
                {
                    Console.Error.WriteLine($"rejected: {result.Error.Name()}");
                    return 2;
                }
                JsonObject shown = result.Token!.Claims.DeepClone().AsObject();
                if (shown.ContainsKey("skey"))
                    shown["skey"] = "<redacted>";
                Console.WriteLine($"ok: player {result.Token.PlayerId}, key {result.Token.KeyId}");
                Console.WriteLine(shown.ToJsonString(Vectors.Pretty));
                return 0;
            }
            case "gen-vectors":
                File.WriteAllText(Need(opts, "out"), Vectors.Generate());
                Console.WriteLine($"wrote {opts["out"]}");
                return 0;
            default:
                return Usage();
        }
    }
    catch (Exception e) when (e is UsageException or FormatException or IOException or ArgumentException)
    {
        Console.Error.WriteLine($"error: {e.Message}");
        return 1;
    }
}

static int Usage()
{
    Console.Error.WriteLine("""
        usage:
          xitoken-cli keygen --out <file> [--kid <kid>]           new identity or signing key; prints its server id
          xitoken-cli keyset --identity <identity.key> [--name <display name>] [--days <n>] <kid>=<signing.key> ...
                                                                  signed key set to publish (stdout)
          xitoken-cli show-keyset <file>
          xitoken-cli issue  --issuer <server id> --kid <kid> --key <signing.key> --type <typ> --aud <world id>
                             --sub <account> [--lifetime <seconds, default 60>] [--claims <json object>]
          xitoken-cli verify --trust <server id>=<key set file>[,...] --aud <world id> --type <typ> <token>
          xitoken-cli gen-vectors --out <file>                    regenerates vectors/xitoken.json
        """);
    return 1;
}

static SigningKey LoadKey(string kid, string path) => SigningKey.FromPaserk(kid, File.ReadAllText(path).Trim());

static string Need(Dictionary<string, string> opts, string name) =>
    opts.TryGetValue(name, out string? v) ? v : throw new UsageException($"missing --{name}");

static Dictionary<string, string> ParseOptions(string[] args, out List<string> positional)
{
    var opts = new Dictionary<string, string>();
    positional = [];
    for (int i = 0; i < args.Length; i++)
    {
        if (args[i].StartsWith("--", StringComparison.Ordinal) && i + 1 < args.Length)
            opts[args[i][2..]] = args[++i];
        else
            positional.Add(args[i]);
    }
    return opts;
}

sealed class UsageException(string message) : Exception(message);

/// <summary>Builds vectors/xitoken.json: fixed keys, fixed payloads, expected outcomes.</summary>
static class Vectors
{
    public static readonly JsonSerializerOptions Pretty = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private const string Now = "2026-10-01T12:00:00Z";

    private static SigningKey Seeded(string kid, int first) => SigningKey.FromSeed(kid, Enumerable.Range(first, 32).Select(i => (byte)i).ToArray());

    public static string Generate()
    {
        SigningKey identity = Seeded("identity", 1);       // the provider
        SigningKey signing = Seeded("2026-10", 33);
        SigningKey forged = Seeded("2026-10", 101);        // not in any key set
        SigningKey otherIdentity = Seeded("identity", 65); // a second provider
        SigningKey worldIdentity = Seeded("identity", 140);
        string provider = identity.ServerId, other = otherIdentity.ServerId, world = worldIdentity.ServerId;
        Rfc3339.TryParse(Now, out DateTimeOffset now);

        string keyset = KeySet.Create(identity, "Test Provider", [signing], now.AddDays(-1), now.AddDays(30));
        string otherKeyset = KeySet.Create(otherIdentity, "Other Provider", [Seeded("2026-10", 200)], now.AddDays(-1));

        // --- key set cases
        var keysetCases = new JsonArray();
        void KeysetCase(string name, string token, string trust, string expect) =>
            keysetCases.Add(new JsonObject { ["name"] = name, ["token"] = token, ["trust"] = trust, ["expect"] = expect });

        KeysetCase("valid", keyset, provider, "ok");
        KeysetCase("trusted under another id", keyset, other, "error");
        KeysetCase("expired", KeySet.Create(identity, null, [signing], now.AddDays(-30), now.AddDays(-1)), provider, "error");
        KeysetCase("iss is not the identity key's id",
            Paseto.Sign(identity, Utf8($"{{\"typ\":\"xi.keyset/1\",\"iss\":\"{other}\",\"iat\":\"{Now}\",\"keys\":[]}}"),
                        Utf8($"{{\"idk\":\"{identity.PublicPaserk}\"}}")), other, "error");
        KeysetCase("idk swapped for another key",
            Paseto.Sign(identity, Utf8($"{{\"typ\":\"xi.keyset/1\",\"iss\":\"{other}\",\"iat\":\"{Now}\",\"keys\":[]}}"),
                        Utf8($"{{\"idk\":\"{otherIdentity.PublicPaserk}\"}}")), other, "error");
        KeysetCase("duplicate kid",
            Paseto.Sign(identity, Utf8($"{{\"typ\":\"xi.keyset/1\",\"iss\":\"{provider}\",\"iat\":\"{Now}\",\"keys\":[" +
                        $"{{\"kid\":\"a\",\"public\":\"{signing.PublicPaserk}\"}},{{\"kid\":\"a\",\"public\":\"{forged.PublicPaserk}\"}}]}}"),
                        Utf8($"{{\"idk\":\"{identity.PublicPaserk}\"}}")), provider, "error");
        KeysetCase("a token is not a key set", new TokenIssuer(provider, signing).Issue("xi.account/1", world, "1", TimeSpan.FromMinutes(1)), provider, "error");

        // --- token cases
        string skey = Base64Url.Encode(Enumerable.Range(0xA0, 20).Select(i => (byte)i).ToArray());
        const string jti = "AAECAwQFBgcICQoLDA0ODw";
        string footer = $"{{\"iss\":\"{provider}\",\"kid\":\"2026-10\"}}";

        string Payload(string typ = WorldEntry.Type, string iat = "2026-10-01T11:59:30Z", string exp = "2026-10-01T12:00:30Z",
                       string? iss = null, string? aud = null, string extra = "") =>
            $"{{\"iss\":\"{iss ?? provider}\",\"aud\":\"{aud ?? world}\",\"sub\":\"1001\",\"typ\":\"{typ}\",\"jti\":\"{jti}\",\"iat\":\"{iat}\",\"exp\":\"{exp}\"{extra}}}";

        string entry = $",\"char\":{{\"id\":4097,\"name\":\"Ayame\"}},\"client\":{{\"ip\":\"192.168.1.50\",\"version\":\"20160203_0\",\"expansions\":30}},\"skey\":\"{skey}\"";

        var cases = new JsonArray();
        void Case(string name, string payload, string expect, string type = WorldEntry.Type,
                  string? foot = null, SigningKey? signer = null, int repeat = 1, bool? worldEntry = null, string? tokenOverride = null)
        {
            foot ??= footer;
            string token = tokenOverride ?? Paseto.Sign(signer ?? signing, Utf8(payload), Utf8(foot));
            var c = new JsonObject
            {
                ["name"] = name,
                ["payload"] = payload,
                ["footer"] = foot,
                ["resign"] = tokenOverride is null && signer is null,
                ["token"] = token,
                ["type"] = type,
                ["expect"] = expect,
            };
            if (repeat > 1)
                c["repeat"] = repeat;
            if (worldEntry is { } we)
                c["world_entry_valid"] = we;
            cases.Add(c);
        }

        Case("world-entry ok", Payload(extra: entry), "ok", worldEntry: true);
        Case("account ok", Payload(typ: "xi.account/1"), "ok", type: "xi.account/1");
        Case("offset and fractional times ok", Payload(iat: "2026-10-01T13:59:30.123456+02:00", exp: "2026-10-01T07:00:30-05:00"), "ok");
        Case("expired within skew still ok", Payload(iat: "2026-10-01T11:58:00Z", exp: "2026-10-01T11:59:40Z"), "ok");
        Case("expired", Payload(iat: "2026-10-01T11:58:00Z", exp: "2026-10-01T11:59:30Z"), "expired");
        Case("issued in the future", Payload(iat: "2026-10-01T12:01:00Z", exp: "2026-10-01T12:02:00Z"), "not_yet_valid");
        Case("nbf in the future", Payload(extra: ",\"nbf\":\"2026-10-01T12:00:31Z\""), "not_yet_valid");
        Case("lifetime too long", Payload(iat: "2026-10-01T11:59:00Z", exp: "2026-10-01T12:09:01Z"), "lifetime_too_long");
        Case("wrong audience", Payload(aud: other), "wrong_audience");
        Case("wrong type", Payload(typ: "xi.account/1"), "wrong_type");
        Case("payload claims another provider", Payload(iss: other), "wrong_issuer");
        Case("unknown kid", Payload(), "unknown_key", foot: $"{{\"iss\":\"{provider}\",\"kid\":\"nope\"}}");
        Case("untrusted provider", Payload(), "unknown_key", foot: $"{{\"iss\":\"xi1.AAAAAAAAAAAAAAAAAAAAAA\",\"kid\":\"2026-10\"}}");
        Case("other provider's key named in footer", Payload(), "bad_signature", foot: $"{{\"iss\":\"{other}\",\"kid\":\"2026-10\"}}");
        Case("signed by another key under the same kid", Payload(), "bad_signature", signer: forged);
        Case("replayed", Payload(), "replayed", repeat: 2);
        Case("missing jti", Payload().Replace($"\"jti\":\"{jti}\",", ""), "bad_claims");
        Case("short jti", Payload().Replace(jti, "abc"), "bad_claims");
        Case("iat not a string", Payload().Replace("\"iat\":\"2026-10-01T11:59:30Z\"", "\"iat\":1790683170"), "bad_claims");
        Case("iat not RFC 3339", Payload(iat: "2026-10-01 11:59:30"), "bad_claims");
        Case("duplicate claim", Payload(extra: ",\"sub\":\"1002\""), "bad_claims");
        Case("payload not an object", "[1,2,3]", "bad_claims");
        Case("footer without iss", Payload(), "malformed", foot: "{\"kid\":\"2026-10\"}");
        Case("footer not JSON", Payload(), "malformed", foot: "2026-10");
        Case("no footer", Payload(), "malformed", foot: "");
        Case("v3 header", Payload(), "malformed",
            tokenOverride: Paseto.Sign(signing, Utf8(Payload()), Utf8(footer)).Replace("v4.public.", "v3.public."));
        Case("padded base64", Payload(), "malformed",
            tokenOverride: Paseto.Sign(signing, Utf8(Payload()), Utf8(footer)) + "=");
        Case("world-entry with a short session key", Payload(extra: entry.Replace(skey, skey[..^4])), "ok", worldEntry: false);
        Case("world-entry with an IPv6 client", Payload(extra: entry.Replace("192.168.1.50", "::1")), "ok", worldEntry: false);

        var doc = new JsonObject
        {
            ["description"] = "xitoken v1 cross-implementation vectors. Generated by `xitoken-cli gen-vectors`; see SPEC.md.",
            ["now"] = Now,
            ["server_ids"] = new JsonArray(
                new JsonObject { ["public"] = identity.PublicPaserk, ["server_id"] = provider },
                new JsonObject { ["public"] = otherIdentity.PublicPaserk, ["server_id"] = other },
                new JsonObject { ["public"] = worldIdentity.PublicPaserk, ["server_id"] = world }),
            ["identity_secret"] = identity.ToPaserk(),
            ["signing_secret"] = signing.ToPaserk(),
            ["keyset_cases"] = keysetCases,
            ["trusted_keysets"] = new JsonArray(
                new JsonObject { ["server_id"] = provider, ["token"] = keyset },
                new JsonObject { ["server_id"] = other, ["token"] = otherKeyset }),
            ["audience"] = world,
            ["clock_skew_seconds"] = 30,
            ["max_lifetime_seconds"] = 300,
            ["cases"] = cases,
        };
        return doc.ToJsonString(Pretty) + "\n";
    }

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
}
