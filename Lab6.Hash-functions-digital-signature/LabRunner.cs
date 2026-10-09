using System.Globalization;

namespace Lab6.Hash_functions_digital_signature;

internal static class LabRunner
{
    public static void Run()
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        Console.WriteLine("Lab 6. Hash Functions and Digital Signatures");
        Console.WriteLine(new string('=', 48));

        var input = ReadLabInput();
        Console.WriteLine();

        RunTask("Task 2 - RSA signature", () =>
        {
            var hash = HashCatalog.SelectForTask2(input.StudentOrder, input.Message);
            PrintHashSelection(hash);

            var keys = RsaSignatureService.GenerateKeys(3072);
            var result = RsaSignatureService.SignAndVerify(hash, keys);
            PrintRsaResult(result);
        });

        Console.WriteLine();

        RunTask("Task 3 - ElGamal signature", () =>
        {
            var hash = HashCatalog.SelectForTask3(input.StudentOrder, input.Message);
            PrintHashSelection(hash);

            var keys = ElGamalSignatureService.GenerateKeys();
            var result = ElGamalSignatureService.SignAndVerify(hash, keys);
            PrintElGamalResult(result);
        });

        Console.WriteLine();
        Console.WriteLine("Laboratory flow completed.");
    }

    private static LabInput ReadLabInput()
    {
        Console.Write("Enter the Lab 2 message m: ");
        var message = Console.ReadLine() ?? string.Empty;

        var studentOrder = ReadInt("Enter your student order k: ");
        return new LabInput(message, studentOrder);
    }

    private static int ReadInt(string prompt)
    {
        while (true)
        {
            Console.Write(prompt);
            var text = Console.ReadLine();

            if (int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) && value > 0)
            {
                return value;
            }

            Console.WriteLine("Please enter a positive integer.");
        }
    }

    private static void RunTask(string title, Action action)
    {
        Console.WriteLine(title);
        Console.WriteLine(new string('-', title.Length));

        try
        {
            action();
        }
        catch (NotSupportedException ex)
        {
            Console.WriteLine(ex.Message);
            Console.WriteLine("For this hash, compute the decimal digest externally in Wolfram Mathematica/WolframAlpha, then continue the report manually.");
        }
    }

    private static void PrintHashSelection(HashSelection hash)
    {
        Console.WriteLine($"Student order k = {hash.StudentOrder}");
        Console.WriteLine($"Hash index i = {hash.HashIndex}");
        Console.WriteLine($"Selected hash = {hash.AlgorithmName}");
        Console.WriteLine($"Digest hex = {hash.DigestHex}");
        Console.WriteLine($"Digest decimal = {hash.DigestDecimal}");
    }

    private static void PrintRsaResult(RsaSignatureResult result)
    {
        Console.WriteLine($"RSA modulus bit length = {result.Keys.ModulusBitLength}");
        Console.WriteLine($"RSA signature (decimal) = {result.SignatureDecimal}");
        Console.WriteLine($"RSA verification = {(result.IsValid ? "valid" : "invalid")}");
    }

    private static void PrintElGamalResult(ElGamalSignatureResult result)
    {
        Console.WriteLine($"ElGamal prime bit length = {result.Keys.PrimeBitLength}");
        Console.WriteLine($"ElGamal r = {result.RDecimal}");
        Console.WriteLine($"ElGamal s = {result.SDecimal}");
        Console.WriteLine($"ElGamal verification = {(result.IsValid ? "valid" : "invalid")}");
    }
}