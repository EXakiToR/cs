using System.Numerics;
using System.Security.Cryptography;

namespace Lab6.Hash_functions_digital_signature;

internal sealed record RsaSignatureMaterial(BigInteger Modulus, BigInteger PublicExponent, BigInteger PrivateExponent)
{
    public int ModulusBitLength => (int)Math.Ceiling(BigInteger.Log(Modulus, 2));
}

internal sealed record RsaSignatureResult(HashSelection Hash, RsaSignatureMaterial Keys, BigInteger Signature, bool IsValid)
{
    public string SignatureDecimal => Signature.ToString(System.Globalization.CultureInfo.InvariantCulture);
}

internal static class RsaSignatureService
{
    public static RsaSignatureMaterial GenerateKeys(int keySizeBits = 3072)
    {
        using var rsa = RSA.Create(keySizeBits);
        var parameters = rsa.ExportParameters(true);

        return new RsaSignatureMaterial(
            ToBigInteger(parameters.Modulus),
            ToBigInteger(parameters.Exponent),
            ToBigInteger(parameters.D));
    }

    public static RsaSignatureResult SignAndVerify(HashSelection hashSelection, RsaSignatureMaterial keys)
    {
        var messageInteger = new BigInteger(hashSelection.DigestBytes, isUnsigned: true, isBigEndian: true);
        var signature = BigInteger.ModPow(messageInteger, keys.PrivateExponent, keys.Modulus);
        var recovered = BigInteger.ModPow(signature, keys.PublicExponent, keys.Modulus);
        var isValid = recovered == messageInteger;

        return new RsaSignatureResult(hashSelection, keys, signature, isValid);
    }

    private static BigInteger ToBigInteger(byte[]? value)
    {
        if (value is null)
        {
            throw new InvalidOperationException("RSA key export returned a null component.");
        }

        return new BigInteger(value, isUnsigned: true, isBigEndian: true);
    }
}