using System.Text;

namespace Lab4.Block_cipher;

internal static class BitUtils
{
    // Check if all characters in the string are valid hexadecimal digits
    public static bool IsHex(string input) => input.All(Uri.IsHexDigit);

    // Convert hexadecimal string to binary bit string (each hex digit ? 4 bits)
    public static string HexToBits(string hex)
    {
        var builder = new StringBuilder(hex.Length * 4);
        foreach (var character in hex)
        {
            // Convert hex character to integer, then to binary, pad to 4 bits
            builder.Append(Convert.ToString(Convert.ToInt32(character.ToString(), 16), 2).PadLeft(4, '0'));
        }

        return builder.ToString();
    }

    // Convert binary bit string to hexadecimal (every 4 bits ? 1 hex digit)
    public static string BitsToHex(string bits)
    {
        var builder = new StringBuilder(bits.Length / 4);
        for (var index = 0; index < bits.Length; index += 4)
        {
            // Convert 4-bit chunk to integer, then to hex format (uppercase)
            builder.Append(Convert.ToInt32(bits.Substring(index, 4), 2).ToString("X"));
        }

        return builder.ToString();
    }

    // Apply a permutation table to a bit string according to DES specification
    public static string Permute(string bits, IReadOnlyList<int> table)
    {
        var builder = new StringBuilder(table.Count);
        foreach (var position in table)
        {
            // Append bit from position (1-indexed in table, convert to 0-indexed for string)
            builder.Append(bits[position - 1]);
        }

        return builder.ToString();
    }

    // Group bits into chunks of specified size, separated by spaces for readability
    public static string GroupBits(string bits, int groupSize = 4)
    {
        var builder = new StringBuilder(bits.Length + bits.Length / groupSize);
        for (var index = 0; index < bits.Length; index += groupSize)
        {
            // Add space before each group (except the first)
            if (index > 0)
            {
                builder.Append(' ');
            }

            // Append the current chunk (handle partial chunks at the end)
            builder.Append(bits.Substring(index, Math.Min(groupSize, bits.Length - index)));
        }

        return builder.ToString();
    }

    // Format a table of integers into a multi-column output
    public static string GroupTable(IReadOnlyList<int> table, int columns)
    {
        var builder = new StringBuilder();
        for (var index = 0; index < table.Count; index++)
        {
            // Add newline after completing a row (except for first element)
            if (index > 0 && index % columns == 0)
            {
                builder.AppendLine();
            }

            // Append the element with 2-character width and a space
            builder.Append($"{table[index],2} ");
        }

        return builder.ToString();
    }

    // Generate a random hexadecimal string of specified length
    public static string RandomHex(int length)
    {
        const string alphabet = "0123456789ABCDEF";
        var builder = new StringBuilder(length);
        var random = Random.Shared;
        for (var index = 0; index < length; index++)
        {
            // Append a random hex digit from the alphabet
            builder.Append(alphabet[random.Next(alphabet.Length)]);
        }

        return builder.ToString();
    }
}
