using System;

namespace Lab3.Polyalphabetic_ciphers;

internal class Program
{
    static void Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("Playfair cipher (Romanian alphabet, 31 letters)\n");

        Console.WriteLine("Allowed letters:");
        Console.WriteLine(PlayfairCipher.AllowedLettersList());
        Console.WriteLine();

        Console.Write("Operation (E)ncrypt / (D)ecrypt: ");
        var op = Console.ReadLine()?.Trim().ToUpperInvariant();
        if (op != "E" && op != "D")
        {
            Console.WriteLine("Invalid operation. Enter 'E' or 'D'.");
            return;
        }

        Console.Write("Key (minimum 7 letters): ");
        var key = Console.ReadLine() ?? string.Empty;
        if (key.Length < 7)
        {
            Console.WriteLine("Key too short. Minimum length is 7.");
            return;
        }

        // validate key letters
        foreach (var ch in key.ToUpperInvariant())
        {
            if (!PlayfairCipher.IsAllowedLetter(ch))
            {
                Console.WriteLine($"Key contains invalid character '{ch}'. Allowed letters: {PlayfairCipher.AllowedLettersList()}");
                return;
            }
        }

        if (op == "E")
        {
            Console.Write("Plaintext (letters only): ");
            var pt = Console.ReadLine() ?? string.Empty;
            // validate and prepare
            var digraphs = PlayfairCipher.PrepareDigraphs(pt, out var error);
            if (!string.IsNullOrEmpty(error))
            {
                Console.WriteLine(error);
                return;
            }

            try
            {
                var cipher = PlayfairCipher.Encrypt(key, pt);
                Console.WriteLine($"\nCiphertext: {cipher}");
                Console.WriteLine("\nMatrix used:");
                PlayfairCipher.PrintMatrix(PlayfairCipher.BuildMatrix(key));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }
        else
        {
            Console.Write("Ciphertext (letters only, even length): ");
            var ct = Console.ReadLine() ?? string.Empty;
            try
            {
                var plain = PlayfairCipher.Decrypt(key, ct);
                Console.WriteLine($"\nDecrypted (raw digraphs result): {plain}");
                Console.WriteLine("\nMatrix used:");
                PlayfairCipher.PrintMatrix(PlayfairCipher.BuildMatrix(key));
                Console.WriteLine("\nNote: You may need to remove filler letters (X or Q) and reinsert spaces manually.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }
    }
}
