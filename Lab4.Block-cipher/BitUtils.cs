using System.Text;

namespace Lab4.Block_cipher;

internal static class BitUtils
{
    public static bool IsHex(string input) => input.All(Uri.IsHexDigit);

    public static string HexToBits(string hex)
    {
        var builder = new StringBuilder(hex.Length * 4);
        foreach (var character in hex)
        {
            builder.Append(Convert.ToString(Convert.ToInt32(character.ToString(), 16), 2).PadLeft(4, '0'));
        }

        return builder.ToString();
    }

    public static string BitsToHex(string bits)
    {
        var builder = new StringBuilder(bits.Length / 4);
        for (var index = 0; index < bits.Length; index += 4)
        {
            builder.Append(Convert.ToInt32(bits.Substring(index, 4), 2).ToString("X"));
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

    public static string GroupBits(string bits, int groupSize = 4)
    {
        var builder = new StringBuilder(bits.Length + bits.Length / groupSize);
        for (var index = 0; index < bits.Length; index += groupSize)
        {
            if (index > 0)
            {
                builder.Append(' ');
            }

            builder.Append(bits.Substring(index, Math.Min(groupSize, bits.Length - index)));
        }

        return builder.ToString();
    }

    public static string GroupTable(IReadOnlyList<int> table, int columns)
    {
        var builder = new StringBuilder();
        for (var index = 0; index < table.Count; index++)
        {
            if (index > 0 && index % columns == 0)
            {
                builder.AppendLine();
            }

            builder.Append($"{table[index],2} ");
        }

        return builder.ToString();
    }

    public static string RandomHex(int length)
    {
        const string alphabet = "0123456789ABCDEF";
        var builder = new StringBuilder(length);
        var random = Random.Shared;
        for (var index = 0; index < length; index++)
        {
            builder.Append(alphabet[random.Next(alphabet.Length)]);
        }

        return builder.ToString();
    }
}
