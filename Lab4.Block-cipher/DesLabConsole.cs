using System.Text;

namespace Lab4.Block_cipher;

internal static class DesLabConsole
{
    public static void Run()
    {
        // Set console output encoding to UTF-8 to support Unicode characters like ⁻¹
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("DES - Task 2.11: ciphertext from L16 and R16");
        Console.WriteLine("Enter each half as 32 bits, 8 hexadecimal digits, or R for random.");
        Console.WriteLine();

        // Read the left half (L16) from user input
        var l16 = ReadHalf("L16");
        // Read the right half (R16) from user input
        var r16 = ReadHalf("R16");
        // Reconstruct ciphertext from L16 and R16 using DES final block logic
        var trace = DesFinalBlock.ReconstructCiphertext(l16, r16);

        Console.WriteLine();
        Console.WriteLine("Final permutation IP⁻¹ table:");
        Console.WriteLine(BitUtils.GroupTable(DesTables.FinalPermutation, 8));
        Console.WriteLine();
        Console.WriteLine("Intermediate steps:");
        Console.WriteLine($"L16       = {BitUtils.GroupBits(l16)}");
        Console.WriteLine($"R16       = {BitUtils.GroupBits(r16)}");
        // Display concatenation of R16 and L16 (the swap operation)
        Console.WriteLine($"R16 || L16 = {BitUtils.GroupBits(trace.PreoutputBits)}");
        // Display result after applying Final Permutation
        Console.WriteLine($"IP⁻¹(R16 || L16) = {BitUtils.GroupBits(trace.CipherBits)}");
        Console.WriteLine();
        Console.WriteLine($"Ciphertext (hex) = {trace.CipherHex}");
    }

    private static string ReadHalf(string name)
    {
        // Loop until valid input is received
        while (true)
        {
            Console.Write($"{name}: ");
            // Read and trim the input from console
            var input = Console.ReadLine()?.Trim();
            // If input is empty or whitespace, skip to next iteration
            if (string.IsNullOrWhiteSpace(input))
            {
                continue;
            }

            // Check if user requested random generation
            if (input.Equals("R", StringComparison.OrdinalIgnoreCase))
            {
                // Generate 8 random hexadecimal characters (32 bits)
                var hex = BitUtils.RandomHex(8);
                Console.WriteLine($"Generated {name} = {hex}");
                // Convert hex to bits and return
                return BitUtils.HexToBits(hex);
            }

            // Check if input is exactly 32 binary digits
            if (input.Length == 32 && input.All(c => c is '0' or '1'))
            {
                // Return the binary input as-is
                return input;
            }

            // Check if input is 8 hexadecimal digits
            if (input.Length == 8 && BitUtils.IsHex(input))
            {
                // Convert hex input to bits and return
                return BitUtils.HexToBits(input.ToUpperInvariant());
            }

            // Display error message for invalid input format
            Console.WriteLine("Invalid value. Enter exactly 32 bits, 8 hexadecimal digits, or R.");
        }
    }
}
