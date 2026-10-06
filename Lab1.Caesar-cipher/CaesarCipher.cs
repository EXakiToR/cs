using System;
using System.Collections.Generic;
using System.Linq;

namespace Lab1.Caesar_cipher
{
    internal static class CaesarCipher
    {
        public static string EncryptSimple(string plain, int k)
        {
            return TransformByAlphabet(plain, k, Alphabet.RomanianAlphabet);
        }

        public static string DecryptSimple(string cipher, int k)
        {
            return TransformByAlphabet(cipher, -k, Alphabet.RomanianAlphabet);
        }

        public static string EncryptWithPermuted(string plain, int k, char[] perm)
        {
            return TransformByAlphabet(plain, k, perm);
        }

        public static string DecryptWithPermuted(string cipher, int k, char[] perm)
        {
            return TransformByAlphabet(cipher, -k, perm);
        }

        private static string TransformByAlphabet(string text, int shift, char[] alphabet)
        {
            int n = alphabet.Length;
            var indexOf = new Dictionary<char, int>();
            for (int i = 0; i < n; i++) indexOf[alphabet[i]] = i;

            var outChars = new char[text.Length];
            for (int i = 0; i < text.Length; i++)
            {
                var c = text[i];
                int pos = indexOf[c];
                int shifted = (pos + shift) % n;
                if (shifted < 0) shifted += n;
                outChars[i] = alphabet[shifted];
            }
            return new string(outChars);
        }

        public static char[] BuildPermutedAlphabet(string keyword)
        {
            var seen = new HashSet<char>();
            var list = new List<char>();
            foreach (var ch in keyword)
            {
                if (!seen.Contains(ch) && Alphabet.RomanianAlphabet.Contains(ch))
                {
                    seen.Add(ch);
                    list.Add(ch);
                }
            }
            foreach (var ch in Alphabet.RomanianAlphabet)
            {
                if (!seen.Contains(ch)) list.Add(ch);
            }
            return list.ToArray();
        }
    }
}
