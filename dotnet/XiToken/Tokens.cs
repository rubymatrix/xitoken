using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace XiToken;

public enum TokenError
{
    None,
    Malformed,
    UnknownKey,
    BadSignature,
    BadClaims,
    WrongIssuer,
    WrongAudience,
    WrongType,
    NotYetValid,
    Expired,
    LifetimeTooLong,
    Replayed,
}

public static class TokenErrors
{
    /// <summary>The SPEC.md error name, e.g. <c>wrong_audience</c>; <c>ok</c> for <see cref="TokenError.None"/>.</summary>
    public static string Name(this TokenError error) => error == TokenError.None
        ? "ok"
        : string.Concat(error.ToString().Select((c, i) => i > 0 && char.IsUpper(c) ? "_" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString()));
}

/// <summary>A token that passed every check in SPEC.md "Verification". <see cref="Claims"/> holds the whole payload.</summary>
public sealed record VerifiedToken(
    string Issuer, string Audience, string Subject, string Type, string Id,
    DateTimeOffset IssuedAt, DateTimeOffset Expires, string KeyId, JsonObject Claims)
{
    /// <summary>The player's global id, <c>iss:sub</c>.</summary>
    public string PlayerId => ServerId.PlayerId(Issuer, Subject);
}

public readonly record struct VerifyResult(TokenError Error, VerifiedToken? Token)
{
    public bool Ok => Error == TokenError.None;
}

/// <summary>Provider side: signs tokens with one of its signing keys.</summary>
public sealed class TokenIssuer
{
    private readonly TimeProvider _clock;

    /// <param name="serverId">This provider's server id (its identity key's <see cref="SigningKey.ServerId"/>).</param>
    /// <param name="key">A signing key listed in this provider's published key set.</param>
    public TokenIssuer(string serverId, SigningKey key, TimeProvider? clock = null)
    {
        if (!XiToken.ServerId.IsValid(serverId))
            throw new ArgumentException($"'{serverId}' is not a server id", nameof(serverId));
        ServerId = serverId;
        Key = key;
        _clock = clock ?? TimeProvider.System;
    }

    public string ServerId { get; }
    public SigningKey Key { get; }

    /// <param name="claims">Type-specific claims; they may not override the registered ones.</param>
    public string Issue(string type, string audience, string subject, TimeSpan lifetime, JsonObject? claims = null)
    {
        DateTimeOffset now = _clock.GetUtcNow();
        var payload = new JsonObject
        {
            ["iss"] = ServerId,
            ["aud"] = audience,
            ["sub"] = subject,
            ["typ"] = type,
            ["jti"] = Base64Url.Encode(RandomNumberGenerator.GetBytes(16)),
            ["iat"] = Rfc3339.Format(now),
            ["exp"] = Rfc3339.Format(now + lifetime),
        };
        foreach ((string name, JsonNode? value) in claims ?? [])
        {
            if (payload.ContainsKey(name) || name == "nbf")
                throw new ArgumentException($"claim '{name}' is set by the issuer", nameof(claims));
            payload[name] = value?.DeepClone();
        }

        byte[] footer = Encoding.UTF8.GetBytes(new JsonObject { ["iss"] = ServerId, ["kid"] = Key.KeyId }.ToJsonString());
        return Paseto.Sign(Key, Encoding.UTF8.GetBytes(payload.ToJsonString()), footer);
    }
}

public sealed class VerifierOptions
{
    /// <summary>This world's server id; tokens for any other audience are rejected.</summary>
    public required string Audience { get; init; }
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan MaxLifetime { get; init; } = TimeSpan.FromMinutes(5);
    /// <summary>Required for single-use semantics. Null disables replay protection (tests only).</summary>
    public IReplayGuard? ReplayGuard { get; init; }
    public TimeProvider Clock { get; init; } = TimeProvider.System;
}

/// <summary>World side: verifies tokens against trusted provider keys.</summary>
public sealed class TokenVerifier(IKeyResolver keys, VerifierOptions options)
{
    public const int MaxFooterBytes = 512;
    public const int MaxJsonDepth = 32;

    public VerifyResult Verify(string token, string expectedType)
    {
        // 1-3: parse, find key, check signature
        if (!Paseto.TryParse(token, out _, out _, out byte[] footerBytes) || footerBytes.Length == 0 || footerBytes.Length > MaxFooterBytes)
            return Fail(TokenError.Malformed);
        JsonObject? footer = Json.ParseObject(footerBytes);
        if (footer is null || Json.String(footer, "iss") is not { } keyIssuer || Json.String(footer, "kid") is not { } kid)
            return Fail(TokenError.Malformed);
        TrustedKey? key = keys.Find(keyIssuer, kid);
        if (key is null)
            return Fail(TokenError.UnknownKey);
        if (!Paseto.Verify(token, key.PublicKey, out byte[] payload, out _))
            return Fail(TokenError.BadSignature);

        // 4: claims
        JsonObject? claims = Json.ParseObject(payload);
        if (claims is null ||
            !TryString(claims, "iss", out string iss) || !TryString(claims, "aud", out string aud) ||
            !TryString(claims, "sub", out string sub) || !TryString(claims, "typ", out string typ) ||
            !TryString(claims, "jti", out string jti) || jti.Length < 22 ||
            !TryTime(claims, "iat", out DateTimeOffset iat) || !TryTime(claims, "exp", out DateTimeOffset exp))
            return Fail(TokenError.BadClaims);
        DateTimeOffset? nbf = null;
        if (claims.ContainsKey("nbf"))
        {
            if (!TryTime(claims, "nbf", out DateTimeOffset n))
                return Fail(TokenError.BadClaims);
            nbf = n;
        }

        // 5-7: who and what
        if (iss != key.Issuer)
            return Fail(TokenError.WrongIssuer);
        if (aud != options.Audience)
            return Fail(TokenError.WrongAudience);
        if (typ != expectedType)
            return Fail(TokenError.WrongType);

        // 8: time
        DateTimeOffset now = options.Clock.GetUtcNow();
        TimeSpan skew = options.ClockSkew;
        if (now + skew < iat || (nbf is { } nb && now + skew < nb))
            return Fail(TokenError.NotYetValid);
        if (now - skew >= exp)
            return Fail(TokenError.Expired);
        if (exp - iat > options.MaxLifetime)
            return Fail(TokenError.LifetimeTooLong);

        // 9: single use
        if (options.ReplayGuard is { } guard && !guard.TryConsume(iss, jti, exp + skew))
            return Fail(TokenError.Replayed);

        return new VerifyResult(TokenError.None, new VerifiedToken(iss, aud, sub, typ, jti, iat, exp, kid, claims));
    }

    private static VerifyResult Fail(TokenError error) => new(error, null);

    private static bool TryString(JsonObject claims, string name, out string value)
    {
        value = Json.String(claims, name) ?? "";
        return value.Length > 0;
    }

    private static bool TryTime(JsonObject claims, string name, out DateTimeOffset value)
    {
        value = default;
        return TryString(claims, name, out string text) && Rfc3339.TryParse(text, out value);
    }
}
