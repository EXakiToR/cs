using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Lab6.Hash_functions_digital_signature;

internal sealed record ElGamalKeyMaterial(BigInteger PrimeP, BigInteger GeneratorG, BigInteger PrivateX, BigInteger PublicY)
{
    public int PrimeBitLength => (int)Math.Ceiling(BigInteger.Log(PrimeP, 2));
}

internal sealed record ElGamalSignatureResult(HashSelection Hash, ElGamalKeyMaterial Keys, BigInteger EphemeralK, BigInteger R, BigInteger S, bool IsValid)
{
    public string RDecimal => R.ToString(System.Globalization.CultureInfo.InvariantCulture);
    public string SDecimal => S.ToString(System.Globalization.CultureInfo.InvariantCulture);
}

internal static class ElGamalSignatureService
{
    public static ElGamalKeyMaterial GenerateKeys()
    {
        var p = ParseBigInteger(PrimePText);
        var g = new BigInteger(2);
        var x = RandomInRange(BigInteger.One, p - 1);
        var y = BigInteger.ModPow(g, x, p);

        return new ElGamalKeyMaterial(p, g, x, y);
    }

    public static ElGamalSignatureResult SignAndVerify(HashSelection hashSelection, ElGamalKeyMaterial keys)
    {
        var pMinusOne = keys.PrimeP - 1;
        var h = new BigInteger(hashSelection.DigestBytes, isUnsigned: true, isBigEndian: true) % pMinusOne;

        if (h.Sign < 0)
        {
            h += pMinusOne;
        }

        BigInteger k;
        do
        {
            k = RandomInRange(BigInteger.One, pMinusOne);
        }
        while (BigInteger.GreatestCommonDivisor(k, pMinusOne) != BigInteger.One);

        var r = BigInteger.ModPow(keys.GeneratorG, k, keys.PrimeP);
        var kInverse = ModInverse(k, pMinusOne);
        var s = (kInverse * (h - (keys.PrivateX * r))) % pMinusOne;

        if (s.Sign < 0)
        {
            s += pMinusOne;
        }

        var left = BigInteger.ModPow(keys.GeneratorG, h, keys.PrimeP);
        var right = (BigInteger.ModPow(keys.PublicY, r, keys.PrimeP) * BigInteger.ModPow(r, s, keys.PrimeP)) % keys.PrimeP;
        var isValid = left == right;

        return new ElGamalSignatureResult(hashSelection, keys, k, r, s, isValid);
    }

    private static BigInteger RandomInRange(BigInteger minInclusive, BigInteger maxExclusive)
    {
        if (maxExclusive <= minInclusive)
        {
            throw new ArgumentOutOfRangeException(nameof(maxExclusive));
        }

        var range = maxExclusive - minInclusive;
        var bytes = new byte[range.GetByteCount(isUnsigned: true) + 1];
        BigInteger value;

        do
        {
            RandomNumberGenerator.Fill(bytes.AsSpan(0, bytes.Length - 1));
            bytes[^1] = 0;
            value = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }
        while (value >= range);

        return minInclusive + value;
    }

    private static BigInteger ModInverse(BigInteger value, BigInteger modulus)
    {
        var (gcd, x, _) = ExtendedGcd(value, modulus);
        if (gcd != BigInteger.One)
        {
            throw new InvalidOperationException("The modular inverse does not exist for the chosen nonce.");
        }

        var result = x % modulus;
        return result.Sign < 0 ? result + modulus : result;
    }

    private static (BigInteger Gcd, BigInteger X, BigInteger Y) ExtendedGcd(BigInteger a, BigInteger b)
    {
        if (b == BigInteger.Zero)
        {
            return (a, BigInteger.One, BigInteger.Zero);
        }

        var (gcd, x1, y1) = ExtendedGcd(b, a % b);
        return (gcd, y1, x1 - (a / b) * y1);
    }

    private static BigInteger ParseBigInteger(string text)
    {
        var sanitized = new string(text.Where(char.IsDigit).ToArray());
        return BigInteger.Parse(sanitized, System.Globalization.CultureInfo.InvariantCulture);
    }

    private const string PrimePText = """
        323170060713110073001535134778251633624880571334890751745884
        34139269806834136210002792056362640164685458556357935330816928
        82902308057347262527355474246124574102620252791657297286270630
        03252634282131457669314142236542209411113486299916574782680342
        30553086349050635557712219187890332729569696129743856241741236
        23722519734640269185579776797682301462539793305801522685873076
        11975324364674758554607150438968449403661304976978128542959586
        59597567051283852132784468522925504568272879113720098931873959
        14337417583782600027803497319855206060753323412260325468408812
        0031105907484281003994966956119696956248629032338072839127039
        """;
}