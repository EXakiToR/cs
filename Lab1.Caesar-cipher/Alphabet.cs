using System;
using System.Collections.Generic;
using System.Linq;

namespace Lab1.Caesar_cipher
{
    internal static class Alphabet
    {
        // Romanian alphabet (31 letters) in the order required by the assignment
        // Indices: 0..30
        public static readonly char[] RomanianAlphabet = new char[]
        {
            'A', '\u0102', '\u00C2', // A, Ă, Â
            'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', '\u00CE', // Î
            'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', '\u0218', // Ș
            'T', '\u021A', // Ț
            'U', 'V', 'W', 'X', 'Y', 'Z'
        };

        public static string NormalizeAndStrip(string s)
        {
            if (s == null) return string.Empty;
            // Replace cedilla variants with comma-below variants and convert to uppercase
            s = s.Replace('\u015E', '\u0218').Replace('\u015F', '\u0219') // Ş, ş -> Ș, ș
                 .Replace('\u0162', '\u021A').Replace('\u0163', '\u021B'); // Ţ, ţ -> Ț, ț

            // Decompose so we can catch base letters + combining marks, then
            // replace base+combining (comma-below or cedilla) with the canonical precomposed letters.
            s = s.Normalize(System.Text.NormalizationForm.FormD);
            // combining comma below U+0326 and combining cedilla U+0327
            s = s.Replace("S\u0326", "\u0218").Replace("s\u0326", "\u0219")
                 .Replace("S\u0327", "\u0218").Replace("s\u0327", "\u0219")
                 .Replace("T\u0326", "\u021A").Replace("t\u0326", "\u021B")
                 .Replace("T\u0327", "\u021A").Replace("t\u0327", "\u021B");

            // Recompose and uppercase
            s = s.Normalize(System.Text.NormalizationForm.FormC);
            s = s.ToUpperInvariant();
            // Remove all whitespace
            return new string(s.Where(c => !char.IsWhiteSpace(c)).ToArray());
        }

        public static bool ValidateTextChars(string s, out char invalid)
        {
            foreach (var c in s)
            {
                if (!RomanianAlphabet.Contains(c))
                {
                    invalid = c;
                    return false;
                }
            }
            invalid = '\0';
            return true;
        }

        public static string AllowedLettersString()
        {
            return string.Join(" ", RomanianAlphabet);
        }
    }
}
