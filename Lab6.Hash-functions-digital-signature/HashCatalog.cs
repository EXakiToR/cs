namespace Lab6.Hash_functions_digital_signature;

internal static class HashCatalog
{
    private static readonly string[] Task2Algorithms =
    [
        "MD4",
        "MD5",
        "MD2",
        "MD6-128",
        "MD6-256",
        "MD6-512",
        "SHA-1",
        "SHA-224",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "RipeMD-128",
        "RipeMD-160",
        "RipeMD-256",
        "RipeMD-320",
        "Whirlpool",
        "NTLM",
        "Haval192,3",
        "Haval224,4",
        "Haval256,4"
    ];

    private static readonly string[] Task3Algorithms =
    [
        "NTLM",
        "MD4",
        "MD5",
        "MD2",
        "MD6-128",
        "MD6-256",
        "MD6-512",
        "SHA-1",
        "SHA-224",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
        "RipeMD-128",
        "RipeMD-160",
        "RipeMD-256",
        "RipeMD-320",
        "Whirlpool",
        "Haval192,3",
        "Haval224,4",
        "Haval256,4"
    ];

    public static HashSelection SelectForTask2(int studentOrder, string message)
    {
        return Select(LabTask.Task2, Task2Algorithms, studentOrder, message);
    }

    public static HashSelection SelectForTask3(int studentOrder, string message)
    {
        return Select(LabTask.Task3, Task3Algorithms, studentOrder, message);
    }

    private static HashSelection Select(LabTask task, string[] algorithms, int studentOrder, string message)
    {
        if (studentOrder < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(studentOrder), "Student order must be a positive integer.");
        }

        var hashIndex = ((studentOrder - 1) % algorithms.Length) + 1;
        var algorithmName = algorithms[hashIndex - 1];
        var digest = DigestService.ComputeDigest(algorithmName, message);

        return new HashSelection(task, studentOrder, hashIndex, algorithmName, digest);
    }
}