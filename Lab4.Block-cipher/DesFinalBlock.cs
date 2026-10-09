namespace Lab4.Block_cipher;

internal static class DesFinalBlock
{
    public static (string PreoutputBits, string CipherBits, string CipherHex) ReconstructCiphertext(string l16Bits, string r16Bits)
    {
        if (l16Bits.Length != 32 || r16Bits.Length != 32)
        {
            throw new ArgumentException("L16 and R16 must both be 32 bits long.");
        }

        var preoutput = r16Bits + l16Bits;
        var cipherBits = BitUtils.Permute(preoutput, DesTables.FinalPermutation);
        return (preoutput, cipherBits, BitUtils.BitsToHex(cipherBits));
    }
}
