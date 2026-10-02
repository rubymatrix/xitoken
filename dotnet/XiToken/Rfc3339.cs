using System.Globalization;
using System.Text.RegularExpressions;

namespace XiToken;

/// <summary>RFC 3339 timestamps. Writes <c>YYYY-MM-DDTHH:MM:SSZ</c>; reads any offset, truncating fractional seconds.</summary>
public static partial class Rfc3339
{
    [GeneratedRegex(@"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:([Zz])|([+-])(\d{2}):(\d{2}))$")]
    private static partial Regex Pattern();

    public static string Format(DateTimeOffset time) =>
        time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    public static bool TryParse(string text, out DateTimeOffset time)
    {
        time = default;
        Match m = Pattern().Match(text);
        if (!m.Success)
            return false;

        int G(int i) => int.Parse(m.Groups[i].ValueSpan, CultureInfo.InvariantCulture);
        int offsetMinutes = 0;
        if (!m.Groups[7].Success)
        {
            int oh = G(9), om = G(10);
            if (oh > 23 || om > 59)
                return false;
            offsetMinutes = (oh * 60 + om) * (m.Groups[8].Value == "-" ? -1 : 1);
        }
        try
        {
            time = new DateTimeOffset(G(1), G(2), G(3), G(4), G(5), G(6), TimeSpan.FromMinutes(offsetMinutes));
            return true;
        }
        catch (ArgumentOutOfRangeException)
        {
            return false;
        }
    }
}
