namespace Lab4.Block_cipher;

internal static class DesFinalBlock
{
    // Method to reconstruct the final ciphertext from L16 and R16 after 16 DES rounds
    // Returns a tuple with: (swapped bits before final permutation, cipher bits after permutation, hex representation)
    public static (string PreoutputBits, string CipherBits, string CipherHex) ReconstructCiphertext(string l16Bits, string r16Bits)
    {
        // Validate that both L16 and R16 are exactly 32 bits
        if (l16Bits.Length != 32 || r16Bits.Length != 32)
        {
            throw new ArgumentException("L16 and R16 must both be 32 bits long.");
        }

        // Swap the halves: concatenate R16 || L16 (right half first, then left half)
        var preoutput = r16Bits + l16Bits;
        // Apply the Final Permutation (inverse of Initial Permutation) to produce ciphertext
        var cipherBits = BitUtils.Permute(preoutput, DesTables.FinalPermutation);
        // Return the swapped bits, permuted ciphertext, and hexadecimal representation
        return (preoutput, cipherBits, BitUtils.BitsToHex(cipherBits));
    }
}
