using System.Buffers.Binary;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace XiToken;

/// <summary>PASETO v4.public: Ed25519 over the pre-authentication encoding of header, payload, footer and implicit assertion.</summary>
public static class Paseto
{
    public const string Header = "v4.public.";
    public const int SignatureSize = 64;
    public const int MaxTokenLength = 8192;

    public static string Sign(SigningKey key, byte[] payload, byte[] footer, byte[]? implicitAssertion = null)
    {
        byte[] m2 = Pae(Encoding.ASCII.GetBytes(Header), payload, footer, implicitAssertion ?? []);
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(key.Seed));
        signer.BlockUpdate(m2, 0, m2.Length);
        byte[] sig = signer.GenerateSignature();

        var body = new byte[payload.Length + sig.Length];
        payload.CopyTo(body, 0);
        sig.CopyTo(body, payload.Length);

        string token = Header + Base64Url.Encode(body);
        return footer.Length > 0 ? token + "." + Base64Url.Encode(footer) : token;
    }

    /// <summary>Splits a token without checking the signature. The footer is untrusted until <see cref="Verify"/> succeeds.</summary>
    public static bool TryParse(string token, out byte[] payload, out byte[] signature, out byte[] footer)
    {
        payload = signature = footer = [];
        if (token.Length > MaxTokenLength || !token.StartsWith(Header, StringComparison.Ordinal))
            return false;

        ReadOnlySpan<char> rest = token.AsSpan(Header.Length);
        int dot = rest.IndexOf('.');
        ReadOnlySpan<char> bodyText = dot < 0 ? rest : rest[..dot];
        if (dot >= 0)
        {
            ReadOnlySpan<char> footerText = rest[(dot + 1)..];
            if (footerText.IndexOf('.') >= 0 || footerText.IsEmpty || !Base64Url.TryDecode(footerText, out footer))
                return false;
        }

        if (!Base64Url.TryDecode(bodyText, out byte[] body) || body.Length < SignatureSize)
            return false;

        payload = body[..^SignatureSize];
        signature = body[^SignatureSize..];
        return true;
    }

    /// <summary>Checks a token's signature. Returns the payload and footer only if it is valid.</summary>
    public static bool Verify(string token, ReadOnlySpan<byte> publicKey, out byte[] payload, out byte[] footer, byte[]? implicitAssertion = null)
    {
        if (!TryParse(token, out payload, out byte[] sig, out footer) || publicKey.Length != 32)
        {
            payload = footer = [];
            return false;
        }

        byte[] m2 = Pae(Encoding.ASCII.GetBytes(Header), payload, footer, implicitAssertion ?? []);
        bool valid;
        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(publicKey));
            verifier.BlockUpdate(m2, 0, m2.Length);
            valid = verifier.VerifySignature(sig);
        }
        catch (ArgumentException) // not a valid curve point
        {
            valid = false;
        }
        if (!valid)
        {
            payload = footer = [];
            return false;
        }
        return true;
    }

    /// <summary>PASETO pre-authentication encoding: LE64(count) then LE64(len) || piece for each piece, top bit cleared.</summary>
    public static byte[] Pae(params byte[][] pieces)
    {
        int size = 8 + pieces.Sum(p => 8 + p.Length);
        var output = new byte[size];
        BinaryPrimitives.WriteUInt64LittleEndian(output, (ulong)pieces.Length & long.MaxValue);
        int o = 8;
        foreach (byte[] piece in pieces)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(o), (ulong)piece.Length & long.MaxValue);
            piece.CopyTo(output, o + 8);
            o += 8 + piece.Length;
        }
        return output;
    }
}
