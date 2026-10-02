using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace XiToken;

/// <summary>The outcome of a gateway call: a value, or the gateway's error name (SPEC.md "World gateway API").</summary>
public readonly record struct GatewayResult<T>(T? Value, int Status, string? Error)
{
    public bool Ok => Error is null;

    public static GatewayResult<T> Success(T value) => new(value, 200, null);
    public static GatewayResult<T> Failure(int status, string error) => new(default, status, error);
}

/// <summary>The map server a world sends an admitted character to.</summary>
public sealed record MapAddress(string Ip, ushort Port);

public sealed record CharacterLook(ushort Head, ushort Body, ushort Hands, ushort Legs, ushort Feet, ushort Main, ushort Sub);

/// <summary>A character as <c>GET /xi/v1/characters</c> describes it.</summary>
public sealed record GatewayCharacter(
    uint Id, string Name, bool Rename, ushort Zone, byte Nation, byte Race, byte Face, byte Size, bool Gm,
    byte MainJob, byte MainJobLevel, byte SubJob, CharacterLook Look);

/// <summary>What <c>POST /xi/v1/characters</c> needs; the world picks the starting zone.</summary>
public sealed record NewCharacter(string Name, byte Race, byte Face, byte Size, byte Job, byte Nation);

/// <summary>
/// Provider side of a world's gateway: signs a fresh token for each call and talks to the world over HTTPS, pinning a
/// self-signed certificate when the world publishes a pin. Thread-safe.
/// </summary>
public sealed class GatewayClient : IDisposable
{
    public static readonly TimeSpan AccountTokenLifetime = TimeSpan.FromSeconds(120);

    private readonly HttpClient _http;
    private readonly TokenIssuer _issuer;
    private readonly string _worldId;
    private readonly Uri _base;

    /// <param name="gateway">The world's gateway base URL (its key set's <c>world.gateway</c>).</param>
    /// <param name="worldId">The world's server id; tokens are addressed to it.</param>
    /// <param name="pin">"sha256:..." of the world's certificate, or null to validate the certificate normally.</param>
    public GatewayClient(string gateway, string worldId, TokenIssuer issuer, string? pin = null, TimeSpan? timeout = null)
    {
        _base = new Uri(gateway.TrimEnd('/') + "/");
        _worldId = worldId;
        _issuer = issuer;
        _http = CreateHttpClient(pin, timeout ?? TimeSpan.FromSeconds(5));
    }

    public string WorldId => _worldId;

    public void Dispose() => _http.Dispose();

    /// <summary>An HttpClient that accepts exactly the pinned certificate (when <paramref name="pin"/> is set) or a normally valid one.</summary>
    public static HttpClient CreateHttpClient(string? pin, TimeSpan timeout)
    {
        var handler = new HttpClientHandler();
        if (pin is not null)
            handler.ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
                cert is not null ? PinOf(cert) == pin : errors == SslPolicyErrors.None;
        return new HttpClient(handler) { Timeout = timeout };
    }

    /// <summary>"sha256:" + base64url of the SHA-256 of a certificate's DER encoding (SPEC.md "Transport").</summary>
    public static string PinOf(X509Certificate2 certificate) => "sha256:" + Base64Url.Encode(SHA256.HashData(certificate.RawData));

    /// <summary>Fetches a server's key set and checks it belongs to <paramref name="expectedId"/>.</summary>
    public static async Task<KeySet> FetchKeySetAsync(string url, string expectedId, string? pin = null, CancellationToken cancel = default)
    {
        using HttpClient http = CreateHttpClient(pin, TimeSpan.FromSeconds(10));
        string token = await http.GetStringAsync(url, cancel).ConfigureAwait(false);
        KeySet set = KeySet.Open(token, DateTimeOffset.UtcNow);
        if (set.ServerId != expectedId)
            throw new FormatException($"key set at {url} belongs to {set.ServerId}, not {expectedId}");
        return set;
    }

    /// <summary>Admits a character: <c>POST /xi/v1/world-entry</c>.</summary>
    public async Task<GatewayResult<MapAddress>> EnterAsync(string subject, WorldEntry entry, CancellationToken cancel = default)
    {
        string token = _issuer.Issue(WorldEntry.Type, _worldId, subject, WorldEntry.DefaultLifetime, entry.ToClaims());
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_base, "xi/v1/world-entry"))
        {
            Content = new StringContent(token, Encoding.ASCII, "text/plain"),
        };
        return await SendAsync(request, body =>
            body["map"] is JsonObject map && map["ip"]?.GetValue<string>() is { } ip && map["port"] is JsonValue port
                ? new MapAddress(ip, port.GetValue<ushort>())
                : throw new FormatException("world-entry reply has no map address"), cancel).ConfigureAwait(false);
    }

    public Task<GatewayResult<IReadOnlyList<GatewayCharacter>>> ListCharactersAsync(string subject, CancellationToken cancel = default) =>
        SendAsync(AccountRequest(HttpMethod.Get, "xi/v1/characters", subject), body =>
            (IReadOnlyList<GatewayCharacter>)(body["characters"] as JsonArray ?? throw new FormatException("no characters array"))
                .Select(node => ParseCharacter(node as JsonObject ?? throw new FormatException("character is not an object")))
                .ToList(), cancel);

    public Task<GatewayResult<uint>> CreateCharacterAsync(string subject, NewCharacter character, CancellationToken cancel = default)
    {
        HttpRequestMessage request = AccountRequest(HttpMethod.Post, "xi/v1/characters", subject, new JsonObject
        {
            ["name"] = character.Name,
            ["race"] = character.Race,
            ["face"] = character.Face,
            ["size"] = character.Size,
            ["job"] = character.Job,
            ["nation"] = character.Nation,
        });
        return SendAsync(request, body => body["id"]!.GetValue<uint>(), cancel);
    }

    public Task<GatewayResult<bool>> DeleteCharacterAsync(string subject, uint characterId, CancellationToken cancel = default) =>
        SendAsync(AccountRequest(HttpMethod.Delete, $"xi/v1/characters/{characterId}", subject), _ => true, cancel);

    public Task<GatewayResult<bool>> RenameCharacterAsync(string subject, uint characterId, string name, CancellationToken cancel = default) =>
        SendAsync(AccountRequest(HttpMethod.Post, $"xi/v1/characters/{characterId}/name", subject, new JsonObject { ["name"] = name }), _ => true, cancel);

    private HttpRequestMessage AccountRequest(HttpMethod method, string path, string subject, JsonObject? body = null)
    {
        var request = new HttpRequestMessage(method, new Uri(_base, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("XiToken", _issuer.Issue("xi.account/1", _worldId, subject, AccountTokenLifetime));
        if (body is not null)
            request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        return request;
    }

    private async Task<GatewayResult<T>> SendAsync<T>(HttpRequestMessage request, Func<JsonObject, T> parse, CancellationToken cancel)
    {
        using (request)
        {
            try
            {
                using HttpResponseMessage response = await _http.SendAsync(request, cancel).ConfigureAwait(false);
                string text = await response.Content.ReadAsStringAsync(cancel).ConfigureAwait(false);
                JsonObject? body = null;
                try
                {
                    body = JsonNode.Parse(text) as JsonObject;
                }
                catch (JsonException)
                {
                }

                if (body is null)
                    return GatewayResult<T>.Failure((int)response.StatusCode, "bad_reply");
                if (!response.IsSuccessStatusCode || body["ok"]?.GetValue<bool>() != true)
                    return GatewayResult<T>.Failure((int)response.StatusCode, body["error"]?.GetValue<string>() ?? "bad_reply");
                return GatewayResult<T>.Success(parse(body));
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or FormatException or InvalidOperationException or NullReferenceException)
            {
                return GatewayResult<T>.Failure(0, e is TaskCanceledException ? "timeout" : "unreachable");
            }
        }
    }

    private static GatewayCharacter ParseCharacter(JsonObject c)
    {
        JsonObject job = c["job"] as JsonObject ?? throw new FormatException("character has no job");
        JsonObject look = c["look"] as JsonObject ?? throw new FormatException("character has no look");
        ushort L(string name) => look[name]!.GetValue<ushort>();
        return new GatewayCharacter(
            c["id"]!.GetValue<uint>(), c["name"]!.GetValue<string>(), c["rename"]!.GetValue<bool>(), c["zone"]!.GetValue<ushort>(),
            c["nation"]!.GetValue<byte>(), c["race"]!.GetValue<byte>(), c["face"]!.GetValue<byte>(), c["size"]!.GetValue<byte>(),
            c["gm"]!.GetValue<bool>(), job["main"]!.GetValue<byte>(), job["main_level"]!.GetValue<byte>(), job["sub"]!.GetValue<byte>(),
            new CharacterLook(L("head"), L("body"), L("hands"), L("legs"), L("feet"), L("main"), L("sub")));
    }
}
