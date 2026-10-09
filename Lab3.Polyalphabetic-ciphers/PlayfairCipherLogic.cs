using System;
using System.Collections.Generic;
using System.Linq;

namespace Lab3.Polyalphabetic_ciphers
{
    public static class PlayfairCipher
    {
        // Romanian alphabet (31 letters) in uppercase order
        public static readonly string[] RomanianAlphabet = new[]
        {
            "A","Ă","Â","B","C","D","E","F","G","H","I","Î","J","K","L","M","N","O","P","Q","R","S","Ș","T","Ț","U","V","W","X","Y","Z"
        };

        public static readonly int Rows = 6;
        public static readonly int Cols = 6; // 6x6 = 36 cells (we have 31 letters)

        public static char[,] BuildMatrix(string key)
        {
            var keyChars = key.ToUpperInvariant().ToCharArray()
                .Where(c => IsAllowedLetter(c))
                .Distinct()
                .ToList();

            var matrix = new char[Rows, Cols];
            var placed = new HashSet<char>();
            int r = 0, c = 0;

            void Place(char ch)
            {
                if (placed.Contains(ch)) return;
                matrix[r, c] = ch;
                placed.Add(ch);
                c++;
                if (c >= Cols)
                {
                    c = 0; r++;
                }
            }

            foreach (var ch in keyChars)
            {
                Place(ch);
            }

            // place remaining Romanian letters
            foreach (var s in RomanianAlphabet)
            {
                var ch = s[0];
                if (!placed.Contains(ch)) Place(ch);
            }

            // fill remaining cells with digits if any
            char fill = '0';
            while (r < Rows)
            {
                if (matrix[r, c] == '\0')
                {
                    matrix[r, c] = fill;
                    fill++;
                    c++;
                    if (c >= Cols)
                    {
                        c = 0; r++;
                    }
                }
                else
                {
                    c++;
                    if (c >= Cols) { c = 0; r++; }
                }
            }

            return matrix;
        }

        public static bool IsAllowedLetter(char ch)
        {
            if (char.IsLetter(ch))
            {
                // normalize uppercase char (works for Unicode letters)
                var up = char.ToUpperInvariant(ch);
                return RomanianAlphabet.Contains(up.ToString());
            }
            return false;
        }

        public static string AllowedLettersList()
        {
            return string.Join(' ', RomanianAlphabet);
        }

        public static List<(char, char)> PrepareDigraphs(string input, out string error)
        {
            error = string.Empty;
            if (string.IsNullOrWhiteSpace(input))
            {
                error = "Input is empty.";
                return new List<(char, char)>();
            }

            var chars = input.ToUpperInvariant().ToCharArray().Where(c => !char.IsWhiteSpace(c)).ToList();
            // validate
            foreach (var ch in chars)
            {
                if (!IsAllowedLetter(ch))
                {
                    error = $"Character '{ch}' is not allowed. Allowed letters are: {AllowedLettersList()}";
                    return new List<(char, char)>();
                }
            }

            var digraphs = new List<(char, char)>();
            int i = 0;
            while (i < chars.Count)
            {
                char a = chars[i];
                char b = '\0';
                if (i + 1 < chars.Count) b = chars[i + 1];

                if (b == '\0')
                {
                    // single last char -> pad with filler 'X' (or 'Q' if 'X')
                    var pad = a == 'X' ? 'Q' : 'X';
                    digraphs.Add((a, pad));
                    i += 1;
                }
                else if (a == b)
                {
                    // insert filler between identical letters
                    var pad = a == 'X' ? 'Q' : 'X';
                    digraphs.Add((a, pad));
                    i += 1; // only advance by one
                }
                else
                {
                    digraphs.Add((a, b));
                    i += 2;
                }
            }

            return digraphs;
        }

        private static (int r, int c) FindPosition(char[,] matrix, char ch)
        {
            for (int i = 0; i < Rows; i++)
            for (int j = 0; j < Cols; j++)
                if (matrix[i, j] == ch) return (i, j);
            throw new ArgumentException($"Character '{ch}' not found in matrix.");
        }

        public static string Encrypt(string key, string plaintext)
        {
            var matrix = BuildMatrix(key);
            var digraphs = PrepareDigraphs(plaintext, out var error);
            if (!string.IsNullOrEmpty(error)) throw new ArgumentException(error);

            var sb = new System.Text.StringBuilder();
            foreach (var (a, b) in digraphs)
            {
                var pa = FindPosition(matrix, a);
                var pb = FindPosition(matrix, b);

                if (pa.r == pb.r)
                {
                    // same row -> next column
                    var ca = matrix[pa.r, (pa.c + 1) % Cols];
                    var cb = matrix[pb.r, (pb.c + 1) % Cols];
                    sb.Append(ca).Append(cb);
                }
                else if (pa.c == pb.c)
                {
                    // same column -> next row
                    var ca = matrix[(pa.r + 1) % Rows, pa.c];
                    var cb = matrix[(pb.r + 1) % Rows, pb.c];
                    sb.Append(ca).Append(cb);
                }
                else
                {
                    var ca = matrix[pa.r, pb.c];
                    var cb = matrix[pb.r, pa.c];
                    sb.Append(ca).Append(cb);
                }
            }

            return sb.ToString();
        }

        public static string Decrypt(string key, string ciphertext)
        {
            var matrix = BuildMatrix(key);
            var chars = ciphertext.ToUpperInvariant().ToCharArray().Where(c => !char.IsWhiteSpace(c)).ToList();
            foreach (var ch in chars)
            {
                if (!IsAllowedLetter(ch))
                {
                    throw new ArgumentException($"Character '{ch}' is not allowed in ciphertext. Allowed: {AllowedLettersList()}");
                }
            }

            if (chars.Count % 2 != 0) throw new ArgumentException("Ciphertext length must be even.");

            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < chars.Count; i += 2)
            {
                var a = chars[i];
                var b = chars[i + 1];
                var pa = FindPosition(matrix, a);
                var pb = FindPosition(matrix, b);

                if (pa.r == pb.r)
                {
                    var ca = matrix[pa.r, (pa.c - 1 + Cols) % Cols];
                    var cb = matrix[pb.r, (pb.c - 1 + Cols) % Cols];
                    sb.Append(ca).Append(cb);
                }
                else if (pa.c == pb.c)
                {
                    var ca = matrix[(pa.r - 1 + Rows) % Rows, pa.c];
                    var cb = matrix[(pb.r - 1 + Rows) % Rows, pb.c];
                    sb.Append(ca).Append(cb);
                }
                else
                {
                    var ca = matrix[pa.r, pb.c];
                    var cb = matrix[pb.r, pa.c];
                    sb.Append(ca).Append(cb);
                }
            }

            return sb.ToString();
        }

        public static void PrintMatrix(char[,] matrix)
        {
            for (int i = 0; i < Rows; i++)
            {
                for (int j = 0; j < Cols; j++)
                {
                    Console.Write(matrix[i, j] + " ");
                }
                Console.WriteLine();
            }
        }
    }
}
