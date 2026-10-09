using System.Globalization;
using System.Text;

namespace Lab4.Block_cipher;

internal static class BitUtils
{
    public static string NormalizeHex(string input, int expectedHexChars)
    {
        var hex = new string(input.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
        if (hex.Length > expectedHexChars)
        {
            hex = hex[..expectedHexChars];
        }

        return hex.PadLeft(expectedHexChars, '0');
    }

    public static bool IsHex(string input) => input.All(c => Uri.IsHexDigit(c));

    public static string HexToBits(string hex)
    {
        var builder = new StringBuilder(hex.Length * 4);
        foreach (var c in hex)
        {
            var value = Convert.ToInt32(c.ToString(), 16);
            builder.Append(Convert.ToString(value, 2).PadLeft(4, '0'));
        }

        return builder.ToString();
    }

    public static string BitsToHex(string bits)
    {
        var builder = new StringBuilder(bits.Length / 4);
        for (var i = 0; i < bits.Length; i += 4)
        {
            var chunk = bits.Substring(i, Math.Min(4, bits.Length - i));
            if (chunk.Length < 4)
            {
                chunk = chunk.PadRight(4, '0');
            }

            builder.Append(Convert.ToString(Convert.ToInt32(chunk, 2), 16));
        }

        return builder.ToString().ToUpperInvariant();
    }

    public static string AsciiToBits(string text)
    {
        var builder = new StringBuilder(text.Length * 8);
        foreach (var c in text)
        {
            builder.Append(Convert.ToString(c, 2).PadLeft(8, '0'));
        }

        return builder.ToString();
    }

    public static string BitsToAscii(string bits)
    {
        var builder = new StringBuilder(bits.Length / 8);
        for (var i = 0; i < bits.Length; i += 8)
        {
            var chunk = bits.Substring(i, 8);
            builder.Append((char)Convert.ToInt32(chunk, 2));
        }

        return builder.ToString();
    }

    public static string Permute(string bits, IReadOnlyList<int> table)
    {
        var builder = new StringBuilder(table.Count);
        foreach (var position in table)
        {
            builder.Append(bits[position - 1]);
        }

        return builder.ToString();
    }

    public static string LeftRotate(string bits, int shift)
    {
        if (bits.Length == 0)
        {
            return bits;
        }

        shift %= bits.Length;
        return bits[shift..] + bits[..shift];
    }

    public static string Xor(string left, string right)
    {
        if (left.Length != right.Length)
        {
            throw new ArgumentException("Bit strings must have the same length.");
        }

        var builder = new StringBuilder(left.Length);
        for (var i = 0; i < left.Length; i++)
        {
            builder.Append(left[i] == right[i] ? '0' : '1');
        }

        return builder.ToString();
    }

    public static string RepeatToLength(string pattern, int length)
    {
        if (pattern.Length == 0)
        {
            throw new ArgumentException("Pattern cannot be empty.");
        }

        var builder = new StringBuilder(length);
        while (builder.Length < length)
        {
            builder.Append(pattern);
        }

        return builder.ToString()[..length];
    }

    public static string GroupBits(string bits, int groupSize = 4, string separator = " ")
    {
        var builder = new StringBuilder(bits.Length + bits.Length / groupSize);
        for (var i = 0; i < bits.Length; i += groupSize)
        {
            if (i > 0)
            {
                builder.Append(separator);
            }

            builder.Append(bits.Substring(i, Math.Min(groupSize, bits.Length - i)));
        }

        return builder.ToString();
    }

    public static string ToBinaryString(int value, int width) => Convert.ToString(value, 2).PadLeft(width, '0');

    public static string RandomHex(int hexChars, Random random)
    {
        const string alphabet = "0123456789ABCDEF";
        var builder = new StringBuilder(hexChars);
        for (var i = 0; i < hexChars; i++)
        {
            builder.Append(alphabet[random.Next(alphabet.Length)]);
        }

        return builder.ToString();
    }

    public static string EnsureLength(string value, int length, char pad = '0')
    {
        if (value.Length > length)
        {
            return value[..length];
        }

        return value.PadLeft(length, pad);
    }
}
