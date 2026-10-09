namespace Lab4.Block_cipher;

internal sealed record SBoxTrace(int BoxIndex, string InputBits, string RowBits, string ColumnBits, int Row, int Column, int Value, string OutputBits);

internal sealed record SBoxesTrace(string InputBits, IReadOnlyList<SBoxTrace> Boxes, string OutputBits);

internal sealed record L1Trace(string MessageBits, string InitialPermutationBits, string L0, string R0, string L1);

internal static class DesRoundFunction
{
    public static L1Trace GetL1FromMessageBits(string messageBits)
    {
        if (messageBits.Length != 64)
        {
            throw new ArgumentException("DES message block must be 64 bits long.");
        }

        var ip = BitUtils.Permute(messageBits, DesTables.InitialPermutation);
        var l0 = ip[..32];
        var r0 = ip[32..];
        return new L1Trace(messageBits, ip, l0, r0, r0);
    }

    public static string ExpandRightHalf(string right32Bits)
    {
        if (right32Bits.Length != 32)
        {
            throw new ArgumentException("Right half must be 32 bits long.");
        }

        return BitUtils.Permute(right32Bits, DesTables.ExpansionPermutation);
    }

    public static string XorWithKey(string expanded48Bits, string key48Bits)
    {
        if (expanded48Bits.Length != 48 || key48Bits.Length != 48)
        {
            throw new ArgumentException("Both inputs must be 48 bits long.");
        }

        return BitUtils.Xor(expanded48Bits, key48Bits);
    }

    public static IReadOnlyList<string> SplitIntoSixBitBlocks(string bits48)
    {
        if (bits48.Length != 48)
        {
            throw new ArgumentException("Input must be 48 bits long.");
        }

        var blocks = new string[8];
        for (var i = 0; i < 8; i++)
        {
            blocks[i] = bits48.Substring(i * 6, 6);
        }

        return blocks;
    }

    public static SBoxesTrace ApplySBoxes(string bits48)
    {
        var blocks = SplitIntoSixBitBlocks(bits48);
        var traces = new List<SBoxTrace>(8);
        var output = new System.Text.StringBuilder(32);

        for (var i = 0; i < 8; i++)
        {
            var block = blocks[i];
            var rowBits = $"{block[0]}{block[5]}";
            var columnBits = block.Substring(1, 4);
            var row = Convert.ToInt32(rowBits, 2);
            var column = Convert.ToInt32(columnBits, 2);
            var value = DesTables.SBoxes[i, row, column];
            var outBits = BitUtils.ToBinaryString(value, 4);
            traces.Add(new SBoxTrace(i + 1, block, rowBits, columnBits, row, column, value, outBits));
            output.Append(outBits);
        }

        return new SBoxesTrace(bits48, traces, output.ToString());
    }

    public static string ApplyPermutationP(string bits32)
    {
        if (bits32.Length != 32)
        {
            throw new ArgumentException("Input must be 32 bits long.");
        }

        return BitUtils.Permute(bits32, DesTables.PermutationP);
    }

    public static string ComputeRightHalf(string left32Bits, string sBoxesOutput32Bits)
    {
        if (left32Bits.Length != 32 || sBoxesOutput32Bits.Length != 32)
        {
            throw new ArgumentException("Both inputs must be 32 bits long.");
        }

        var permuted = ApplyPermutationP(sBoxesOutput32Bits);
        return BitUtils.Xor(left32Bits, permuted);
    }
}
