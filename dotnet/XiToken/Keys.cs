using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;

namespace XiToken;

/// <summary>An Ed25519 key with its key id. Used both as a server's identity key and as a token signing key.</summary>
public sealed class SigningKey
{
    public string KeyId { get; }
    public byte[] Seed { get; }
    public byte[] PublicKey { get; }

    private SigningKey(string keyId, byte[] seed)
    {
        if (!Paserk.IsValidKeyId(keyId))
            throw new ArgumentException($"invalid key id '{keyId}'", nameof(keyId));
        KeyId = keyId;
        Seed = seed;
        PublicKey = new Ed25519PrivateKeyParameters(seed).GeneratePublicKey().GetEncoded();
    }

    public static SigningKey Generate(string keyId) => new(keyId, RandomNumberGenerator.GetBytes(32));

    public static SigningKey FromSeed(string keyId, byte[] seed) =>
        seed.Length == 32 ? new(keyId, (byte[])seed.Clone()) : throw new ArgumentException("seed must be 32 bytes", nameof(seed));

    public static SigningKey FromPaserk(string keyId, string paserk)
    {
        byte[] raw = Paserk.Decode(paserk, Paserk.SecretPrefix, 64);
        var key = new SigningKey(keyId, raw[..32]);
        if (!CryptographicOperations.FixedTimeEquals(key.PublicKey, raw[32..]))
            throw new FormatException("k4.secret public half does not match its seed");
        return key;
    }

    public string ToPaserk() => Paserk.SecretPrefix + Base64Url.Encode([.. Seed, .. PublicKey]);

    public string PublicPaserk => Paserk.PublicPrefix + Base64Url.Encode(PublicKey);

    /// <summary>The server id this key stands for when it is used as an identity key.</summary>
    public string ServerId => XiToken.ServerId.FromPublicKey(PublicKey);
}

public static partial class Paserk
{
    public const string SecretPrefix = "k4.secret.";
    public const string PublicPrefix = "k4.public.";

    [GeneratedRegex("^[A-Za-z0-9._:-]{1,64}$")]
    private static partial Regex KeyIdPattern();

    public static bool IsValidKeyId(string keyId) => KeyIdPattern().IsMatch(keyId);

    public static byte[] Decode(string text, string prefix, int length)
    {
        if (!text.StartsWith(prefix, StringComparison.Ordinal) ||
            !Base64Url.TryDecode(text.AsSpan(prefix.Length), out byte[] raw) || raw.Length != length)
            throw new FormatException($"expected {prefix}<{length} bytes>");
        return raw;
    }
}

/// <summary>Server ids (SPEC.md "Server ids"): <c>xi1.</c> + base64url of the first 16 bytes of a domain-separated SHA-256 of the identity public key.</summary>
public static partial class ServerId
{
    public const string Prefix = "xi1.";
    private static readonly byte[] Domain = Encoding.ASCII.GetBytes("xitoken server id\0");

    [GeneratedRegex("^xi1\\.[A-Za-z0-9_-]{22}$")]
    private static partial Regex Pattern();

    public static string FromPublicKey(ReadOnlySpan<byte> identityPublicKey)
    {
        if (identityPublicKey.Length != 32)
            throw new ArgumentException("identity public key must be 32 bytes");
        byte[] hash = SHA256.HashData([.. Domain, .. identityPublicKey]);
        return Prefix + Base64Url.Encode(hash.AsSpan(0, 16));
    }

    public static bool IsValid(string id) => Pattern().IsMatch(id);

    /// <summary>A player's global id: <c>&lt;provider server id&gt;:&lt;sub&gt;</c>.</summary>
    public static string PlayerId(string providerId, string subject) => providerId + ":" + subject;
}

/// <summary>A signing key a world trusts, and the server it belongs to.</summary>
public sealed record TrustedKey(string Issuer, string KeyId, byte[] PublicKey);

public interface IKeyResolver
{
    TrustedKey? Find(string issuer, string keyId);
}

/// <summary>Key resolver built from signed key sets of the servers an operator chose to trust.</summary>
public sealed class KeySetResolver : IKeyResolver
{
    private readonly Dictionary<string, KeySet> _sets = new(StringComparer.Ordinal);
    private readonly object _lock = new();

    public TrustedKey? Find(string issuer, string keyId)
    {
        lock (_lock)
            return _sets.TryGetValue(issuer, out KeySet? set) ? set.Keys.FirstOrDefault(k => k.KeyId == keyId) : null;
    }

    public IReadOnlyCollection<KeySet> KeySets
    {
        get { lock (_lock) return [.. _sets.Values]; }
    }

    /// <summary>
    /// Opens <paramref name="token"/> and trusts its keys, but only if it belongs to <paramref name="expectedServerId"/>.
    /// A key set older than the one already loaded for that server is refused. Throws <see cref="FormatException"/>.
    /// </summary>
    public KeySet Trust(string token, string expectedServerId, DateTimeOffset? now = null)
    {
        KeySet set = KeySet.Open(token, now ?? DateTimeOffset.UtcNow);
        if (set.ServerId != expectedServerId)
            throw new FormatException($"key set belongs to {set.ServerId}, not {expectedServerId}");
        lock (_lock)
        {
            if (_sets.TryGetValue(set.ServerId, out KeySet? current) && current.IssuedAt > set.IssuedAt)
                throw new FormatException($"key set for {set.ServerId} is older than the one loaded");
            _sets[set.ServerId] = set;
        }
        return set;
    }

    public KeySet TrustFile(string path, string expectedServerId, DateTimeOffset? now = null) =>
        Trust(File.ReadAllText(path), expectedServerId, now);
}

internal static class Json
{
    private static readonly System.Text.Json.JsonDocumentOptions Options = new() { MaxDepth = TokenVerifier.MaxJsonDepth };

    /// <summary>Parses a JSON object with no duplicate keys; null if it is anything else.</summary>
    public static JsonObject? ParseObject(byte[] utf8)
    {
        try
        {
            var node = JsonNode.Parse(utf8, documentOptions: Options) as JsonObject;
            if (node is not null)
                Touch(node);
            return node;
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or ArgumentException or InvalidOperationException or DecoderFallbackException)
        {
            return null;
        }
    }

    // Materialising every nested object makes JsonObject throw on duplicate keys.
    private static void Touch(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var (_, child) in obj)
                    Touch(child);
                break;
            case JsonArray arr:
                foreach (JsonNode? child in arr)
                    Touch(child);
                break;
        }
    }

    public static string? String(JsonObject obj, string name) =>
        obj[name] is JsonValue v && v.GetValueKind() == System.Text.Json.JsonValueKind.String ? v.GetValue<string>() : null;
}
