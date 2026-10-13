using System;
using System.Linq;
using System.Text;

namespace Lab3.Polyalphabetic_ciphers;

internal class Program
{
    static void Main(string[] args)
    {
        Console.InputEncoding = Encoding.UTF8;
        Console.OutputEncoding = Encoding.UTF8;

        while (true)
        {
            Console.WriteLine("Playfair cipher (Romanian alphabet, 31 letters)");
            Console.WriteLine("Allowed letters:");
            Console.WriteLine(PlayfairCipher.AllowedLettersList());
            Console.WriteLine();
            Console.WriteLine("Choose operation:");
            Console.WriteLine("  E - encrypt");
            Console.WriteLine("  D - decrypt");
            Console.WriteLine("  X - exit");
            Console.Write("Operation: ");

            var op = (Console.ReadLine() ?? string.Empty).Trim().ToUpperInvariant();
            if (op == "X")
            {
                return;
            }

            if (op != "E" && op != "D")
            {
                Console.WriteLine("Invalid operation. Enter E, D, or X.");
                Console.WriteLine();
                continue;
            }

            Console.Write("Key (minimum 7 letters): ");
            var key = PlayfairCipher.NormalizeInput(Console.ReadLine() ?? string.Empty);
            var keyLetters = key.Where(c => !char.IsWhiteSpace(c)).ToArray();
            if (keyLetters.Length < 7)
            {
                Console.WriteLine("Key too short. Minimum length is 7 letters.");
                Console.WriteLine();
                continue;
            }

            var invalidKeyChar = keyLetters.FirstOrDefault(ch => !PlayfairCipher.IsAllowedLetter(ch));
            if (invalidKeyChar != default)
            {
                Console.WriteLine($"Key contains invalid character '{invalidKeyChar}'. Allowed letters: {PlayfairCipher.AllowedLettersList()}");
                Console.WriteLine();
                continue;
            }

            if (op == "E")
            {
                Console.Write("Plaintext (letters only): ");
                var pt = Console.ReadLine() ?? string.Empty;
                try
                {
                    var cipher = PlayfairCipher.Encrypt(key, pt);
                    Console.WriteLine();
                    Console.WriteLine($"Ciphertext: {cipher}");
                    Console.WriteLine();
                    Console.WriteLine("Matrix used:");
                    PlayfairCipher.PrintMatrix(PlayfairCipher.BuildMatrix(key));
                    Console.WriteLine();
                    Console.WriteLine("Note: Reinsert spaces manually if needed.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }
            else
            {
                Console.Write("Ciphertext (letters only, even length): ");
                var ct = Console.ReadLine() ?? string.Empty;
                try
                {
                    var plain = PlayfairCipher.Decrypt(key, ct);
                    Console.WriteLine();
                    Console.WriteLine($"Decrypted (raw digraphs result): {plain}");
                    Console.WriteLine();
                    Console.WriteLine("Matrix used:");
                    PlayfairCipher.PrintMatrix(PlayfairCipher.BuildMatrix(key));
                    Console.WriteLine();
                    Console.WriteLine("Note: You may need to remove filler letters (X or Q) and reinsert spaces manually.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error: {ex.Message}");
                }
            }

            Console.WriteLine();
        }
    }
}
