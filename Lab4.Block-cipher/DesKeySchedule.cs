namespace Lab4.Block_cipher;

internal sealed record RoundKeyTrace(int Round, int Shift, string C, string D, string KeyBits, string KeyHex);

internal sealed record KeyScheduleTrace(string KeyBits, string KeyPlusBits, string C0, string D0, IReadOnlyList<RoundKeyTrace> Rounds);

internal static class DesKeySchedule
{
    public static KeyScheduleTrace FromKeyBits(string keyBits)
    {
        if (keyBits.Length != 64)
        {
            throw new ArgumentException("DES key must be 64 bits long.");
        }

        var keyPlus = BitUtils.Permute(keyBits, DesTables.PermutedChoice1);
        var c = keyPlus[..28];
        var d = keyPlus[28..];
        var rounds = new List<RoundKeyTrace>(16);

        for (var round = 1; round <= 16; round++)
        {
            var shift = DesTables.KeyShifts[round - 1];
            c = BitUtils.LeftRotate(c, shift);
            d = BitUtils.LeftRotate(d, shift);
            var key = BitUtils.Permute(c + d, DesTables.PermutedChoice2);
            rounds.Add(new RoundKeyTrace(round, shift, c, d, key, BitUtils.BitsToHex(key)));
        }

        return new KeyScheduleTrace(keyBits, keyPlus, keyPlus[..28], keyPlus[28..], rounds);
    }

    public static (string C, string D) GetCiDi(string keyPlusBits, int round)
    {
        if (keyPlusBits.Length != 56)
        {
            throw new ArgumentException("K+ must be 56 bits long.");
        }

        if (round is < 0 or > 16)
        {
            throw new ArgumentOutOfRangeException(nameof(round), "Round must be between 0 and 16.");
        }

        var c = keyPlusBits[..28];
        var d = keyPlusBits[28..];
        if (round == 0)
        {
            return (c, d);
        }

        for (var i = 1; i <= round; i++)
        {
            var shift = DesTables.KeyShifts[i - 1];
            c = BitUtils.LeftRotate(c, shift);
            d = BitUtils.LeftRotate(d, shift);
        }

        return (c, d);
    }

    public static string GetRoundKey(string keyPlusBits, int round)
    {
        var (c, d) = GetCiDi(keyPlusBits, round);
        return BitUtils.Permute(c + d, DesTables.PermutedChoice2);
    }

    public static IReadOnlyList<RoundKeyTrace> GetAllRoundKeys(string keyPlusBits)
    {
        if (keyPlusBits.Length != 56)
        {
            throw new ArgumentException("K+ must be 56 bits long.");
        }

        var c = keyPlusBits[..28];
        var d = keyPlusBits[28..];
        var rounds = new List<RoundKeyTrace>(16);

        for (var round = 1; round <= 16; round++)
        {
            var shift = DesTables.KeyShifts[round - 1];
            c = BitUtils.LeftRotate(c, shift);
            d = BitUtils.LeftRotate(d, shift);
            var key = BitUtils.Permute(c + d, DesTables.PermutedChoice2);
            rounds.Add(new RoundKeyTrace(round, shift, c, d, key, BitUtils.BitsToHex(key)));
        }

        return rounds;
    }
}
