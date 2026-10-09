namespace Lab6.Hash_functions_digital_signature;

internal enum LabTask
{
    Task2,
    Task3
}

internal sealed record LabInput(string Message, int StudentOrder);

internal sealed record HashSelection(LabTask Task, int StudentOrder, int HashIndex, string AlgorithmName, byte[] DigestBytes)
{
    public string DigestHex => Convert.ToHexString(DigestBytes);

    public string DigestDecimal => new System.Numerics.BigInteger(DigestBytes, isUnsigned: true, isBigEndian: true).ToString(System.Globalization.CultureInfo.InvariantCulture);
}