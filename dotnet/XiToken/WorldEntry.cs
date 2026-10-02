using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace XiToken;

/// <summary>Claims of an <c>xi.world-entry/1</c> token (SPEC.md). <see cref="SessionKey"/> is a live secret: never log it.</summary>
public sealed record WorldEntry(
    uint CharId,
    string? CharName,
    string ClientIp,
    string ClientVersion,
    uint ClientExpansions,
    byte[] SessionKey)
{
    public const string Type = "xi.world-entry/1";
    public const int SessionKeySize = 20;
    public static readonly TimeSpan DefaultLifetime = TimeSpan.FromSeconds(60);

    public JsonObject ToClaims()
    {
        if (SessionKey.Length != SessionKeySize)
            throw new InvalidOperationException("session key must be 20 bytes");
        if (!IsIPv4(ClientIp))
            throw new InvalidOperationException("client ip must be a dotted IPv4 address");
        if (ClientVersion.Length > 16)
            throw new InvalidOperationException("client version is at most 16 characters");

        var character = new JsonObject { ["id"] = CharId };
        if (CharName is not null)
            character["name"] = CharName;
        return new JsonObject
        {
            ["char"] = character,
            ["client"] = new JsonObject { ["ip"] = ClientIp, ["version"] = ClientVersion, ["expansions"] = ClientExpansions },
            ["skey"] = Base64Url.Encode(SessionKey),
        };
    }

    public static WorldEntry? FromClaims(JsonObject claims)
    {
        if (claims["char"] is not JsonObject character || claims["client"] is not JsonObject client)
            return null;
        if (!TryUInt(character["id"], out uint charId) || !TryUInt(client["expansions"], out uint expansions))
            return null;

        string? name = null;
        if (character.ContainsKey("name") && !TryString(character["name"], out name))
            return null;
        if (!TryString(client["ip"], out string? ip) || !IsIPv4(ip) ||
            !TryString(client["version"], out string? version) || version.Length > 16 ||
            !TryString(claims["skey"], out string? skeyText) ||
            !Base64Url.TryDecode(skeyText, out byte[] skey) || skey.Length != SessionKeySize)
            return null;

        return new WorldEntry(charId, name, ip, version, expansions, skey);
    }

    /// <summary>The client address as LSB stores it in <c>accounts_sessions.client_addr</c> (first octet in the low byte).</summary>
    public uint ClientAddrLsb() => BitConverter.ToUInt32(IPAddress.Parse(ClientIp).GetAddressBytes());

    public override string ToString() =>
        $"WorldEntry {{ CharId = {CharId}, CharName = {CharName}, ClientIp = {ClientIp}, ClientVersion = {ClientVersion}, ClientExpansions = {ClientExpansions}, SessionKey = <redacted> }}";

    private static bool IsIPv4(string ip) =>
        IPAddress.TryParse(ip, out IPAddress? a) && a.AddressFamily == AddressFamily.InterNetwork && a.ToString() == ip;

    private static bool TryUInt(JsonNode? node, out uint value)
    {
        value = 0;
        return node is JsonValue v && v.GetValueKind() == JsonValueKind.Number && v.TryGetValue(out value);
    }

    private static bool TryString(JsonNode? node, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out string? value)
    {
        value = null;
        if (node is not JsonValue v || v.GetValueKind() != JsonValueKind.String)
            return false;
        value = v.GetValue<string>();
        return true;
    }
}
