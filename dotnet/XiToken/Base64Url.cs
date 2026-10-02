namespace XiToken;

/// <summary>Unpadded base64url (RFC 4648 §5). Decoding is strict: no padding, no whitespace, canonical trailing bits.</summary>
public static class Base64Url
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var sb = new System.Text.StringBuilder((data.Length * 4 + 2) / 3);
        int i = 0;
        for (; i + 3 <= data.Length; i += 3)
        {
            int v = data[i] << 16 | data[i + 1] << 8 | data[i + 2];
            sb.Append(Alphabet[v >> 18 & 63]).Append(Alphabet[v >> 12 & 63]).Append(Alphabet[v >> 6 & 63]).Append(Alphabet[v & 63]);
        }
        int rem = data.Length - i;
        if (rem == 1)
        {
            int v = data[i] << 16;
            sb.Append(Alphabet[v >> 18 & 63]).Append(Alphabet[v >> 12 & 63]);
        }
        else if (rem == 2)
        {
            int v = data[i] << 16 | data[i + 1] << 8;
            sb.Append(Alphabet[v >> 18 & 63]).Append(Alphabet[v >> 12 & 63]).Append(Alphabet[v >> 6 & 63]);
        }
        return sb.ToString();
    }

    public static bool TryDecode(ReadOnlySpan<char> text, out byte[] data)
    {
        data = [];
        if (text.Length % 4 == 1)
            return false;

        var output = new byte[text.Length * 3 / 4];
        int acc = 0, bits = 0, o = 0;
        foreach (char c in text)
        {
            int v = Value(c);
            if (v < 0)
                return false;
            acc = acc << 6 | v;
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                output[o++] = (byte)(acc >> bits);
                acc &= (1 << bits) - 1;
            }
        }
        if (acc != 0) // non-canonical leftover bits
            return false;

        data = output;
        return true;
    }

    private static int Value(char c) => c switch
    {
        >= 'A' and <= 'Z' => c - 'A',
        >= 'a' and <= 'z' => c - 'a' + 26,
        >= '0' and <= '9' => c - '0' + 52,
        '-' => 62,
        '_' => 63,
        _ => -1,
    };
}
