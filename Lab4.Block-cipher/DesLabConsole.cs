using System.Text;

namespace Lab4.Block_cipher;

internal static class DesLabConsole
{
    public static void Run()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("DES - Task 2.11: ciphertext from L16 and R16");
        Console.WriteLine("Enter each half as 32 bits, 8 hexadecimal digits, or R for random.");
        Console.WriteLine();

        var l16 = ReadHalf("L16");
        var r16 = ReadHalf("R16");
        var trace = DesFinalBlock.ReconstructCiphertext(l16, r16);

        Console.WriteLine();
        Console.WriteLine("Final permutation IP⁻¹ table:");
        Console.WriteLine(BitUtils.GroupTable(DesTables.FinalPermutation, 8));
        Console.WriteLine();
        Console.WriteLine("Intermediate steps:");
        Console.WriteLine($"L16       = {BitUtils.GroupBits(l16)}");
        Console.WriteLine($"R16       = {BitUtils.GroupBits(r16)}");
        Console.WriteLine($"R16 || L16 = {BitUtils.GroupBits(trace.PreoutputBits)}");
        Console.WriteLine($"IP⁻¹(R16 || L16) = {BitUtils.GroupBits(trace.CipherBits)}");
        Console.WriteLine();
        Console.WriteLine($"Ciphertext (hex) = {trace.CipherHex}");
    }

    private static string ReadHalf(string name)
    {
        while (true)
        {
            Console.Write($"{name}: ");
            var input = Console.ReadLine()?.Trim();
            if (string.IsNullOrWhiteSpace(input))
            {
                continue;
            }

            if (input.Equals("R", StringComparison.OrdinalIgnoreCase))
            {
                var hex = BitUtils.RandomHex(8);
                Console.WriteLine($"Generated {name} = {hex}");
                return BitUtils.HexToBits(hex);
            }

            if (input.Length == 32 && input.All(c => c is '0' or '1'))
            {
                return input;
            }

            if (input.Length == 8 && BitUtils.IsHex(input))
            {
                return BitUtils.HexToBits(input.ToUpperInvariant());
            }

            Console.WriteLine("Invalid value. Enter exactly 32 bits, 8 hexadecimal digits, or R.");
        }
    }
}
