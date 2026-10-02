using System.Text;
using System.Text.Json.Nodes;

namespace XiToken;

/// <summary>What a world's key set says about the world (SPEC.md "Keys and key sets").</summary>
/// <param name="Search">The world's search server as "IPv4:port", or null.</param>
public sealed record WorldInfo(string Gateway, uint Expansions, string? Search = null);

/// <summary>The opened contents of a signed key set (SPEC.md "Keys and key sets").</summary>
public sealed record KeySet(string ServerId, string? Name, DateTimeOffset IssuedAt, DateTimeOffset? Expires, IReadOnlyList<TrustedKey> Keys, WorldInfo? World = null)
{
    public const string Type = "xi.keyset/1";

    /// <summary>Signs a key set with the server's identity key. Worlds pass <paramref name="world"/>.</summary>
    public static string Create(SigningKey identity, string? name, IEnumerable<SigningKey> signingKeys, DateTimeOffset issuedAt,
                                DateTimeOffset? expires = null, WorldInfo? world = null)
    {
        var keys = new JsonArray();
        foreach (SigningKey key in signingKeys)
            keys.Add(new JsonObject { ["kid"] = key.KeyId, ["public"] = key.PublicPaserk });
        var payload = new JsonObject { ["keys"] = keys };
        if (world is not null)
        {
            var w = new JsonObject { ["gateway"] = world.Gateway, ["expansions"] = world.Expansions };
            if (world.Search is not null)
                w["search"] = world.Search;
            payload["world"] = w;
        }
        return SignedDocument.Sign(identity, Type, name, issuedAt, expires, payload);
    }

    /// <summary>Checks a signed key set and returns its contents. Throws <see cref="FormatException"/> if it is not valid at <paramref name="now"/>.</summary>
    public static KeySet Open(string token, DateTimeOffset now)
    {
        var doc = SignedDocument.Open(token, Type, now);

        if (doc.Payload["keys"] is not JsonArray array)
            throw new FormatException("key set has no keys array");
        var keys = new List<TrustedKey>();
        foreach (JsonNode? entry in array)
        {
            if (entry is not JsonObject obj || Json.String(obj, "kid") is not { } kid || Json.String(obj, "public") is not { } pub)
                throw new FormatException("key entries need kid and public");
            if (!Paserk.IsValidKeyId(kid))
                throw new FormatException($"invalid key id '{kid}'");
            if (keys.Any(k => k.KeyId == kid))
                throw new FormatException($"duplicate key id '{kid}'");
            keys.Add(new TrustedKey(doc.ServerId, kid, Paserk.Decode(pub, Paserk.PublicPrefix, 32)));
        }

        WorldInfo? world = null;
        if (doc.Payload.ContainsKey("world"))
        {
            if (doc.Payload["world"] is not JsonObject w || Json.String(w, "gateway") is not { Length: > 0 } gateway ||
                w["expansions"] is not JsonValue ev || !ev.TryGetValue(out uint expansions))
                throw new FormatException("key set world needs gateway and expansions");
            string? search = null;
            if (w.ContainsKey("search") && (search = Json.String(w, "search")) is null)
                throw new FormatException("key set world search must be a string");
            world = new WorldInfo(gateway, expansions, search);
        }
        return new KeySet(doc.ServerId, doc.Name, doc.IssuedAt, doc.Expires, keys, world);
    }
}

/// <summary>One server listed in a registry.</summary>
public sealed record RegistryEntry(string Id, string Role, string KeySetUrl, string? Pin = null)
{
    public const string World = "world";
    public const string Provider = "provider";
}

/// <summary>A signed list of servers (SPEC.md "World list and registry"). Listing only says where to find a server; its key set is still checked against its id.</summary>
public sealed record Registry(string ServerId, string? Name, DateTimeOffset IssuedAt, DateTimeOffset? Expires, IReadOnlyList<RegistryEntry> Servers)
{
    public const string Type = "xi.registry/1";

    public static string Create(SigningKey identity, string? name, IEnumerable<RegistryEntry> servers, DateTimeOffset issuedAt, DateTimeOffset? expires = null)
    {
        var list = new JsonArray();
        foreach (RegistryEntry entry in servers)
        {
            var obj = new JsonObject { ["id"] = entry.Id, ["role"] = entry.Role, ["keyset"] = entry.KeySetUrl };
            if (entry.Pin is not null)
                obj["pin"] = entry.Pin;
            list.Add(obj);
        }
        return SignedDocument.Sign(identity, Type, name, issuedAt, expires, new JsonObject { ["servers"] = list });
    }

    /// <summary>Opens a registry, but only if it belongs to <paramref name="expectedServerId"/>. Throws <see cref="FormatException"/>.</summary>
    public static Registry Open(string token, string expectedServerId, DateTimeOffset now)
    {
        var doc = SignedDocument.Open(token, Type, now);
        if (doc.ServerId != expectedServerId)
            throw new FormatException($"registry belongs to {doc.ServerId}, not {expectedServerId}");
        if (doc.Payload["servers"] is not JsonArray array)
            throw new FormatException("registry has no servers array");

        var servers = new List<RegistryEntry>();
        foreach (JsonNode? node in array)
        {
            if (node is not JsonObject obj || Json.String(obj, "id") is not { } id || !XiToken.ServerId.IsValid(id) ||
                Json.String(obj, "role") is not { } role || Json.String(obj, "keyset") is not { } url ||
                !Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) || (uri.Scheme != "https" && uri.Scheme != "http"))
                throw new FormatException("registry entries need id, role and an http(s) keyset URL");
            if (servers.Any(s => s.Id == id))
                throw new FormatException($"server {id} is listed twice");
            string? pin = null;
            if (obj.ContainsKey("pin") && (pin = Json.String(obj, "pin")) is null)
                throw new FormatException("pin must be a string");
            servers.Add(new RegistryEntry(id, role, url, pin));
        }
        return new Registry(doc.ServerId, doc.Name, doc.IssuedAt, doc.Expires, servers);
    }
}

/// <summary>Documents signed by a server's identity key: key sets and registries.</summary>
internal static class SignedDocument
{
    public sealed record Opened(string ServerId, string? Name, DateTimeOffset IssuedAt, DateTimeOffset? Expires, JsonObject Payload);

    public static string Sign(SigningKey identity, string type, string? name, DateTimeOffset issuedAt, DateTimeOffset? expires, JsonObject body)
    {
        var payload = new JsonObject
        {
            ["typ"] = type,
            ["iss"] = identity.ServerId,
            ["iat"] = Rfc3339.Format(issuedAt),
        };
        if (name is not null)
            payload["name"] = name;
        if (expires is { } exp)
            payload["exp"] = Rfc3339.Format(exp);
        foreach ((string key, JsonNode? value) in body)
            payload[key] = value?.DeepClone();
        byte[] footer = Encoding.UTF8.GetBytes(new JsonObject { ["idk"] = identity.PublicPaserk }.ToJsonString());
        return Paseto.Sign(identity, Encoding.UTF8.GetBytes(payload.ToJsonString()), footer);
    }

    public static Opened Open(string token, string type, DateTimeOffset now)
    {
        token = token.Trim();
        if (!Paseto.TryParse(token, out _, out _, out byte[] footerBytes) ||
            Json.ParseObject(footerBytes)?["idk"] is not JsonValue idkNode || !idkNode.TryGetValue(out string? idk))
            throw new FormatException($"not a signed {type} document");
        byte[] identityKey = Paserk.Decode(idk, Paserk.PublicPrefix, 32);
        if (!Paseto.Verify(token, identityKey, out byte[] payloadBytes, out _))
            throw new FormatException($"{type} signature is not valid");

        JsonObject payload = Json.ParseObject(payloadBytes) ?? throw new FormatException($"{type} payload is not a JSON object");
        string serverId = ServerId.FromPublicKey(identityKey);
        if (Json.String(payload, "typ") != type)
            throw new FormatException($"not an {type} document");
        if (Json.String(payload, "iss") != serverId)
            throw new FormatException($"{type} iss does not match its identity key");
        if (!Rfc3339.TryParse(Json.String(payload, "iat") ?? "", out DateTimeOffset iat))
            throw new FormatException($"{type} has no valid iat");
        DateTimeOffset? exp = null;
        if (payload.ContainsKey("exp"))
        {
            if (!Rfc3339.TryParse(Json.String(payload, "exp") ?? "", out DateTimeOffset e))
                throw new FormatException($"{type} exp is not valid");
            if (now >= e)
                throw new FormatException($"{type} has expired");
            exp = e;
        }
        string? name = null;
        if (payload.ContainsKey("name") && (name = Json.String(payload, "name")) is null)
            throw new FormatException($"{type} name must be a string");
        return new Opened(serverId, name, iat, exp, payload);
    }
}
