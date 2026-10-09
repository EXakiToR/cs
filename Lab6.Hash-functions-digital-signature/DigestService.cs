using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace Lab6.Hash_functions_digital_signature;

internal static class DigestService
{
    public static byte[] ComputeDigest(string algorithmName, string message)
    {
        return algorithmName switch
        {
            "MD2" => ComputeBouncyCastleDigest(new MD2Digest(), message, Encoding.UTF8),
            "MD4" => ComputeBouncyCastleDigest(new MD4Digest(), message, Encoding.UTF8),
            "MD5" => ComputeBouncyCastleDigest(new MD5Digest(), message, Encoding.UTF8),
            "NTLM" => ComputeBouncyCastleDigest(new MD4Digest(), message, Encoding.Unicode),
            "SHA-1" => ComputeBouncyCastleDigest(new Sha1Digest(), message, Encoding.UTF8),
            "SHA-224" => ComputeBouncyCastleDigest(new Sha224Digest(), message, Encoding.UTF8),
            "SHA-256" => ComputeBouncyCastleDigest(new Sha256Digest(), message, Encoding.UTF8),
            "SHA-384" => ComputeBouncyCastleDigest(new Sha384Digest(), message, Encoding.UTF8),
            "SHA-512" => ComputeBouncyCastleDigest(new Sha512Digest(), message, Encoding.UTF8),
            "SHA3-224" => ComputeBouncyCastleDigest(new Sha3Digest(224), message, Encoding.UTF8),
            "SHA3-256" => ComputeBouncyCastleDigest(new Sha3Digest(256), message, Encoding.UTF8),
            "SHA3-384" => ComputeBouncyCastleDigest(new Sha3Digest(384), message, Encoding.UTF8),
            "SHA3-512" => ComputeBouncyCastleDigest(new Sha3Digest(512), message, Encoding.UTF8),
            "RipeMD-128" => ComputeBouncyCastleDigest(new RipeMD128Digest(), message, Encoding.UTF8),
            "RipeMD-160" => ComputeBouncyCastleDigest(new RipeMD160Digest(), message, Encoding.UTF8),
            "RipeMD-256" => ComputeBouncyCastleDigest(new RipeMD256Digest(), message, Encoding.UTF8),
            "RipeMD-320" => ComputeBouncyCastleDigest(new RipeMD320Digest(), message, Encoding.UTF8),
            "Whirlpool" => ComputeBouncyCastleDigest(new WhirlpoolDigest(), message, Encoding.UTF8),
            "Haval192,3" or "Haval224,4" or "Haval256,4" => throw new NotSupportedException("Haval variants are not available in the installed hash library; compute them externally in Wolfram Mathematica/WolframAlpha for the laboratory report."),
            "MD6-128" or "MD6-256" or "MD6-512" => throw new NotSupportedException("MD6 variants are not available in the installed hash library; compute them externally in Wolfram Mathematica/WolframAlpha for the laboratory report."),
            _ => throw new NotSupportedException($"Unsupported hash algorithm '{algorithmName}'.")
        };
    }

    private static byte[] ComputeBouncyCastleDigest(IDigest digest, string message, Encoding encoding)
    {
        var input = encoding.GetBytes(message);
        digest.BlockUpdate(input, 0, input.Length);
        var output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return output;
    }

    private static byte[] ComputeHashLibHaval(string message, int hashSize, int passes)
    {
        throw new NotSupportedException($"Haval variants are not available in the installed hash library; compute '{hashSize},{passes}' externally for the laboratory report.");
    }
}