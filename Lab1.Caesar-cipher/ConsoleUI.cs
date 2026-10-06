using System;

namespace Lab1.Caesar_cipher
{
    internal static class ConsoleUI
    {
        public static void RunLoop()
        {
            while (true)
            {
                Console.WriteLine();
                Console.WriteLine("Romanian Caesar Cipher - choose an option:");
                Console.WriteLine("1 - Simple Caesar cipher");
                Console.WriteLine("2 - Caesar cipher with keyword permutation");
                Console.WriteLine("0 - Exit");
                Console.Write("Option: ");
                var opt = Console.ReadLine()?.Trim();
                if (opt == "0") break;
                if (opt == "1") RunSimpleCaesar();
                else if (opt == "2") RunPermutedCaesar();
                else Console.WriteLine("Invalid option.");
            }
        }

        private static void RunSimpleCaesar()
        {
            Console.WriteLine("Simple Caesar cipher (Romanian alphabet)");
            bool encrypt = AskEncryptOrDecrypt();
            int key = AskKey();
            string input = AskText();
            string normalized = Alphabet.NormalizeAndStrip(input);
            if (!Alphabet.ValidateTextChars(normalized, out char invalid))
            {
                Console.WriteLine($"Invalid character '{invalid}' (U+{((int)invalid):X4}). Allowed letters are: {Alphabet.AllowedLettersString()}");
                return;
            }

            string output = encrypt ? CaesarCipher.EncryptSimple(normalized, key) : CaesarCipher.DecryptSimple(normalized, key);
            Console.WriteLine("Result: " + output);
        }

        private static void RunPermutedCaesar()
        {
            Console.WriteLine("Caesar cipher with keyword permutation (Romanian alphabet)");
            bool encrypt = AskEncryptOrDecrypt();
            int key = AskKey();
            string keyword = AskKeyword();
            if (keyword == null) return; // AskKeyword already printed messages

            // Build permuted alphabet and display it
            var perm = CaesarCipher.BuildPermutedAlphabet(keyword);
            Console.WriteLine("Permuted alphabet:");
            Console.WriteLine(string.Join("", perm));

            string input = AskText();
            string normalized = Alphabet.NormalizeAndStrip(input);
            if (!Alphabet.ValidateTextChars(normalized, out char invalid))
            {
                Console.WriteLine($"Invalid character '{invalid}' (U+{((int)invalid):X4}). Allowed letters are: {Alphabet.AllowedLettersString()}");
                return;
            }

            string output = encrypt ? CaesarCipher.EncryptWithPermuted(normalized, key, perm) : CaesarCipher.DecryptWithPermuted(normalized, key, perm);
            Console.WriteLine("Result: " + output);
        }

        private static bool AskEncryptOrDecrypt()
        {
            while (true)
            {
                Console.Write("Operation - (E)ncrypt or (D)ecrypt? ");
                var ans = Console.ReadLine()?.Trim().ToUpperInvariant();
                if (ans == "E" || ans == "ENCRYPT") return true;
                if (ans == "D" || ans == "DECRYPT") return false;
                Console.WriteLine("Please enter E for encryption or D for decryption.");
            }
        }

        private static int AskKey()
        {
            while (true)
            {
                Console.Write($"Enter numeric key k (1..{Alphabet.RomanianAlphabet.Length - 1}): ");
                var s = Console.ReadLine()?.Trim();
                if (int.TryParse(s, out int k) && k >= 1 && k <= Alphabet.RomanianAlphabet.Length - 1) return k;
                Console.WriteLine($"Invalid key. Allowed values are integers from 1 to {Alphabet.RomanianAlphabet.Length - 1}.");
            }
        }

        private static string AskText()
        {
            Console.Write("Enter text (letters and spaces allowed): ");
            return Console.ReadLine() ?? string.Empty;
        }

        private static string AskKeyword()
        {
            while (true)
            {
                Console.Write($"Enter keyword (Romanian letters only, at least 7 characters): ");
                var kw = Console.ReadLine() ?? string.Empty;
                kw = Alphabet.NormalizeAndStrip(kw); // uppercase and remove spaces
                if (kw.Length < 7)
                {
                    Console.WriteLine("Keyword too short. It must have at least 7 letters after removing spaces.");
                    continue;
                }
                if (!Alphabet.ValidateTextChars(kw, out char invalid))
                {
                    Console.WriteLine($"Invalid character '{invalid}' (U+{((int)invalid):X4}) in keyword. Allowed letters are: {Alphabet.AllowedLettersString()}");
                    continue;
                }
                return kw;
            }
        }
    }
}
