
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Lab3.Polyalphabetic_ciphers
{
    public static class PlayfairCipher
    {
        // Playfair is a polygraphic substitution cipher.
        // It encrypts two letters at a time (digraphs).

        // Romanian alphabet with 30 letters.
        // W is excluded so all letters fit into a 5x6 matrix.
        public static readonly string[] RomanianAlphabet = new[]
        {
            "A", "Ă", "Â", "B", "C", "D",
            "E", "F", "G", "H", "I", "Î",
            "J", "K", "L", "M", "N", "O",
            "P", "Q", "R", "S", "Ș", "T",
            "Ț", "U", "V", "X", "Y", "Z"
        };

        public static readonly int Rows = 5;
        public static readonly int Cols = 6;

        // Normalizes Romanian characters.
        // Some Romanian letters have multiple Unicode representations.
        // This ensures that equivalent characters are treated equally.
        public static string NormalizeInput(string input)
        {
            return (input ?? string.Empty)
                .Normalize(NormalizationForm.FormC)
                .Replace('Ş', 'Ș')
                .Replace('ş', 'ș')
                .Replace('Ţ', 'Ț')
                .Replace('ţ', 'ț');
        }

        // Builds the Playfair matrix using the keyword.
        // First, unique letters from the key are inserted.
        // Then, the remaining alphabet letters are added.
        public static char[,] BuildMatrix(string key)
        {
            var keyChars = NormalizeInput(key)
                .ToUpperInvariant()
                .ToCharArray()
                .Where(c => IsAllowedLetter(c)) // Remove invalid characters
                .Distinct()                     // Remove repeated letters
                .ToList();

            // Create a matrix with 5 rows and 6 columns.
            var matrix = new char[Rows, Cols];

            // HashSet allows us to check whether a letter
            // has already been inserted into the matrix.
            var placed = new HashSet<char>();

            // Current position in the matrix.
            int r = 0;
            int c = 0;

            // Local function for inserting a letter.
            void Place(char ch)
            {
                // Do not insert the same letter twice.
                if (placed.Contains(ch))
                    return;

                matrix[r, c] = ch;
                placed.Add(ch);

                // Move to the next column.
                c++;

                // If the row is full, move to the next row.
                if (c >= Cols)
                {
                    c = 0;
                    r++;
                }
            }

            // Step 1: Insert unique letters from the keyword.
            foreach (var ch in keyChars)
            {
                Place(ch);
            }

            // Step 2: Insert the remaining Romanian letters.
            foreach (var s in RomanianAlphabet)
            {
                var ch = s[0];

                if (!placed.Contains(ch))
                    Place(ch);
            }

            return matrix;
        }

        // Checks whether a character belongs to our alphabet.
        public static bool IsAllowedLetter(char ch)
        {
            if (char.IsLetter(ch))
            {
                // Convert the character to uppercase.
                var up = char.ToUpperInvariant(ch);

                // Standardize Romanian diacritics.
                if (up == 'Ş')
                    up = 'Ș';

                if (up == 'Ţ')
                    up = 'Ț';

                return RomanianAlphabet.Contains(up.ToString());
            }

            return false;
        }

        // Returns all allowed letters as a string.
        // Used mainly when displaying validation errors.
        public static string AllowedLettersList()
        {
            return string.Join(' ', RomanianAlphabet);
        }

        // Prepares plaintext by dividing it into pairs of letters.
        // Playfair cannot encrypt a single letter independently.
        public static List<(char, char)> PrepareDigraphs(
            string input,
            out string error)
        {
            error = string.Empty;

            var normalized = NormalizeInput(input);

            // Check whether the input is empty.
            if (string.IsNullOrWhiteSpace(normalized))
            {
                error = "Input is empty.";
                return new List<(char, char)>();
            }

            // Convert to uppercase and remove whitespace.
            var chars = normalized
                .ToUpperInvariant()
                .ToCharArray()
                .Where(c => !char.IsWhiteSpace(c))
                .ToList();

            // Validate every character.
            foreach (var ch in chars)
            {
                if (!IsAllowedLetter(ch))
                {
                    error = $"Character '{ch}' is not allowed. " +
                            $"Allowed letters are: {AllowedLettersList()}";

                    return new List<(char, char)>();
                }
            }

            // Each tuple stores one pair of letters.
            var digraphs = new List<(char, char)>();

            int i = 0;

            while (i < chars.Count)
            {
                char a = chars[i];
                char b = '\0';

                // Read the next character if it exists.
                if (i + 1 < chars.Count)
                    b = chars[i + 1];

                if (b == '\0')
                {
                    // Case 1: Only one letter remains.
                    // Add X to complete the pair.
                    // If the letter is X, use Q instead.
                    var pad = a == 'X' ? 'Q' : 'X';

                    digraphs.Add((a, pad));

                    i += 1;
                }
                else if (a == b)
                {
                    // Case 2: Two identical letters.
                    // Playfair requires different letters in a pair.
                    // Insert a filler between them.
                    var pad = a == 'X' ? 'Q' : 'X';

                    digraphs.Add((a, pad));

                    // Advance only one position because
                    // the second repeated letter must still be processed.
                    i += 1;
                }
                else
                {
                    // Case 3: Two different letters.
                    // Add them as a normal digraph.
                    digraphs.Add((a, b));

                    i += 2;
                }
            }

            return digraphs;
        }

        // Finds the row and column of a letter in the matrix.
        // Returns a tuple containing (row, column).
        private static (int r, int c) FindPosition(
            char[,] matrix,
            char ch)
        {
            for (int i = 0; i < Rows; i++)
            {
                for (int j = 0; j < Cols; j++)
                {
                    if (matrix[i, j] == ch)
                        return (i, j);
                }
            }

            throw new ArgumentException(
                $"Character '{ch}' not found in matrix.");
        }

        // Encrypts plaintext using the Playfair algorithm.
        public static string Encrypt(string key, string plaintext)
        {
            // Generate the matrix from the key.
            var matrix = BuildMatrix(key);

            // Divide plaintext into digraphs.
            var digraphs = PrepareDigraphs(
                plaintext,
                out var error);

            if (!string.IsNullOrEmpty(error))
                throw new ArgumentException(error);

            // StringBuilder stores the encrypted result.
            var sb = new StringBuilder();

            // Process each pair of letters.
            foreach (var (a, b) in digraphs)
            {
                // Find both letters in the matrix.
                var pa = FindPosition(matrix, a);
                var pb = FindPosition(matrix, b);

                if (pa.r == pb.r)
                {
                    // RULE 1: SAME ROW
                    // Replace each letter with the letter to its right.
                    // Modulo (%) wraps from the last column to the first.

                    var ca = matrix[pa.r, (pa.c + 1) % Cols];
                    var cb = matrix[pb.r, (pb.c + 1) % Cols];

                    sb.Append(ca).Append(cb);
                }
                else if (pa.c == pb.c)
                {
                    // RULE 2: SAME COLUMN
                    // Replace each letter with the letter below it.
                    // Modulo wraps from the last row to the first.

                    var ca = matrix[(pa.r + 1) % Rows, pa.c];
                    var cb = matrix[(pb.r + 1) % Rows, pb.c];

                    sb.Append(ca).Append(cb);
                }
                else
                {
                    // RULE 3: RECTANGLE
                    // The letters form opposite corners of a rectangle.
                    // Keep each letter's row but exchange their columns.

                    var ca = matrix[pa.r, pb.c];
                    var cb = matrix[pb.r, pa.c];

                    sb.Append(ca).Append(cb);
                }
            }

            return sb.ToString();
        }

        // Decrypts ciphertext using the same key matrix.
        public static string Decrypt(string key, string ciphertext)
        {
            var matrix = BuildMatrix(key);

            // Normalize, convert to uppercase and remove spaces.
            var chars = NormalizeInput(ciphertext)
                .ToUpperInvariant()
                .ToCharArray()
                .Where(c => !char.IsWhiteSpace(c))
                .ToList();

            // Check whether all ciphertext letters are allowed.
            foreach (var ch in chars)
            {
                if (!IsAllowedLetter(ch))
                {
                    throw new ArgumentException(
                        $"Character '{ch}' is not allowed in ciphertext. " +
                        $"Allowed: {AllowedLettersList()}");
                }
            }

            // Ciphertext must contain an even number of letters
            // because Playfair always encrypts pairs.
            if (chars.Count % 2 != 0)
            {
                throw new ArgumentException(
                    "Ciphertext length must be even.");
            }

            var sb = new StringBuilder();

            // Process ciphertext two letters at a time.
            for (int i = 0; i < chars.Count; i += 2)
            {
                var a = chars[i];
                var b = chars[i + 1];

                var pa = FindPosition(matrix, a);
                var pb = FindPosition(matrix, b);

                if (pa.r == pb.r)
                {
                    // RULE 1: SAME ROW
                    // During decryption, move LEFT instead of right.
                    // Adding Cols prevents negative indexes.

                    var ca = matrix[
                        pa.r,
                        (pa.c - 1 + Cols) % Cols
                    ];

                    var cb = matrix[
                        pb.r,
                        (pb.c - 1 + Cols) % Cols
                    ];

                    sb.Append(ca).Append(cb);
                }
                else if (pa.c == pb.c)
                {
                    // RULE 2: SAME COLUMN
                    // During decryption, move UP instead of down.

                    var ca = matrix[
                        (pa.r - 1 + Rows) % Rows,
                        pa.c
                    ];

                    var cb = matrix[
                        (pb.r - 1 + Rows) % Rows,
                        pb.c
                    ];

                    sb.Append(ca).Append(cb);
                }
                else
                {
                    // RULE 3: RECTANGLE
                    // Same operation as encryption:
                    // keep the rows and exchange the columns.

                    var ca = matrix[pa.r, pb.c];
                    var cb = matrix[pb.r, pa.c];

                    sb.Append(ca).Append(cb);
                }
            }

            // Filler letters (X or Q) are not automatically removed.
            // They may also be legitimate plaintext letters.
            return sb.ToString();
        }

        // Displays the generated Playfair matrix in the console.
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
