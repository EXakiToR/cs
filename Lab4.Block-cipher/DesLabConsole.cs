using System.Text;

namespace Lab4.Block_cipher;

internal static class DesLabConsole
{
    public static void Run()
    {
        while (true)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine();
            Console.WriteLine("DES Laboratory");
            Console.WriteLine("1 - 2.1 K+ from an 8-character key");
            Console.WriteLine("2 - 2.2 Ci and Di for a given round");
            Console.WriteLine("3 - 2.3 Round key Ki for a given round");
            Console.WriteLine("4 - 2.5 All 16 round keys");
            Console.WriteLine("5 - 2.4 L1 from an 8-character message");
            Console.WriteLine("6 - 2.6 B1..B8 from Ki and Ri-1");
            Console.WriteLine("7 - 2.7 S1(B1)..S8(B8)");
            Console.WriteLine("8 - 2.8 Ri from L(i-1) and S-box output");
            Console.WriteLine("9 - 2.9 Sj(Bj) for a given j");
            Console.WriteLine("10 - 2.10 Ri from S-box outputs and L(i-1)");
            Console.WriteLine("11 - 2.11 Ciphertext from L16 and R16");
            Console.WriteLine("0 - Exit");
            Console.Write("Choose: ");

            var choice = Console.ReadLine()?.Trim();
            Console.WriteLine();

            switch (choice)
            {
                case "1":
                    RunKeyPlusTask();
                    break;
                case "2":
                    RunCiDiTask();
                    break;
                case "3":
                    RunRoundKeyTask();
                    break;
                case "4":
                    RunAllRoundKeysTask();
                    break;
                case "5":
                    RunL1Task();
                    break;
                case "6":
                    RunBBlocksTask();
                    break;
                case "7":
                    RunSBoxesTask();
                    break;
                case "8":
                    RunRiTask();
                    break;
                case "9":
                    RunSingleSBoxTask();
                    break;
                case "10":
                    RunRiFromSBoxesTask();
                    break;
                case "11":
                    RunCiphertextTask();
                    break;
                case "0":
                    return;
                default:
                    Console.WriteLine("Unknown option.");
                    break;
            }
        }
    }

    private static void RunKeyPlusTask()
    {
        var keyBits = ReadKeyBits();
        var trace = DesKeySchedule.FromKeyBits(keyBits);

        Console.WriteLine("Task 2.1 - K+ from the DES key");
        PrintKeyTrace(trace, includeRounds: false);
        Console.WriteLine();
    }

    private static void RunCiDiTask()
    {
        var keyBits = ReadKeyBits();
        var trace = DesKeySchedule.FromKeyBits(keyBits);
        var round = ReadRoundNumber();
        var (c, d) = DesKeySchedule.GetCiDi(trace.KeyPlusBits, round);

        Console.WriteLine("Task 2.2 - Ci and Di for a given round");
        PrintKeyTrace(trace, includeRounds: true, maxRound: round);
        Console.WriteLine($"C{round} = {BitUtils.GroupBits(c)}");
        Console.WriteLine($"D{round} = {BitUtils.GroupBits(d)}");
        Console.WriteLine();
    }

    private static void RunRoundKeyTask()
    {
        var keyBits = ReadKeyBits();
        var trace = DesKeySchedule.FromKeyBits(keyBits);
        var round = ReadRoundNumber();
        var roundKey = DesKeySchedule.GetRoundKey(trace.KeyPlusBits, round);

        Console.WriteLine("Task 2.3 - Round key Ki for a given round");
        PrintKeyTrace(trace, includeRounds: true, maxRound: round);
        Console.WriteLine($"K{round} = {BitUtils.GroupBits(roundKey)}");
        Console.WriteLine($"K{round} (hex) = {BitUtils.BitsToHex(roundKey)}");
        Console.WriteLine();
    }

    private static void RunAllRoundKeysTask()
    {
        var keyBits = ReadKeyBits();
        var trace = DesKeySchedule.FromKeyBits(keyBits);
        var rounds = DesKeySchedule.GetAllRoundKeys(trace.KeyPlusBits);

        Console.WriteLine("Task 2.5 - All 16 round keys");
        PrintKeyTrace(trace, includeRounds: false);
        foreach (var round in rounds)
        {
            Console.WriteLine($"Round {round.Round}, shift {round.Shift}");
            Console.WriteLine($"C{round.Round} = {BitUtils.GroupBits(round.C)}");
            Console.WriteLine($"D{round.Round} = {BitUtils.GroupBits(round.D)}");
            Console.WriteLine($"K{round.Round} = {BitUtils.GroupBits(round.KeyBits)}");
            Console.WriteLine($"K{round.Round} (hex) = {round.KeyHex}");
            Console.WriteLine();
        }
    }

    private static void RunL1Task()
    {
        var messageBits = ReadMessageBits();
        var trace = DesRoundFunction.GetL1FromMessageBits(messageBits);

        Console.WriteLine("Task 2.4 - L1 from an 8-character message");
        Console.WriteLine($"Message bits = {BitUtils.GroupBits(trace.MessageBits)}");
        Console.WriteLine($"IP(message)  = {BitUtils.GroupBits(trace.InitialPermutationBits)}");
        Console.WriteLine($"L0           = {BitUtils.GroupBits(trace.L0)}");
        Console.WriteLine($"R0           = {BitUtils.GroupBits(trace.R0)}");
        Console.WriteLine($"L1           = {BitUtils.GroupBits(trace.L1)}");
        Console.WriteLine();
    }

    private static void RunBBlocksTask()
    {
        var rightBits = ReadBits("Enter Ri-1 (32 bits, hex, or R for random): ", 32);
        var keyBits = ReadBits("Enter Ki (48 bits, hex, or R for random): ", 48);
        var expanded = DesRoundFunction.ExpandRightHalf(rightBits);
        var xored = DesRoundFunction.XorWithKey(expanded, keyBits);
        var blocks = DesRoundFunction.SplitIntoSixBitBlocks(xored);

        Console.WriteLine("Task 2.6 - B1..B8 from Ki and Ri-1");
        Console.WriteLine($"Ri-1        = {BitUtils.GroupBits(rightBits)}");
        Console.WriteLine($"E(Ri-1)     = {BitUtils.GroupBits(expanded)}");
        Console.WriteLine($"Ki          = {BitUtils.GroupBits(keyBits)}");
        Console.WriteLine($"Ki XOR E(Ri-1) = {BitUtils.GroupBits(xored, 6)}");
        for (var i = 0; i < blocks.Count; i++)
        {
            Console.WriteLine($"B{i + 1} = {blocks[i]}");
        }
        Console.WriteLine();
    }

    private static void RunSBoxesTask()
    {
        var input48 = ReadBits("Enter B1..B8 as 48 bits, hex, or R for random: ", 48);
        var trace = DesRoundFunction.ApplySBoxes(input48);

        Console.WriteLine("Task 2.7 - S1(B1)..S8(B8)");
        Console.WriteLine($"Input 48 bits = {BitUtils.GroupBits(trace.InputBits, 6)}");
        foreach (var box in trace.Boxes)
        {
            Console.WriteLine($"S{box.BoxIndex}: input={box.InputBits}, row={box.RowBits} ({box.Row}), column={box.ColumnBits} ({box.Column}), value={box.Value}, output={box.OutputBits}");
        }
        Console.WriteLine($"S-box output = {BitUtils.GroupBits(trace.OutputBits)}");
        Console.WriteLine();
    }

    private static void RunRiTask()
    {
        var leftBits = ReadBits("Enter L(i-1) (32 bits, hex, or R for random): ", 32);
        var sboxBits = ReadBits("Enter the S-box output (32 bits, hex, or R for random): ", 32);
        var pOutput = DesRoundFunction.ApplyPermutationP(sboxBits);
        var ri = BitUtils.Xor(leftBits, pOutput);

        Console.WriteLine("Task 2.8 - Ri from L(i-1) and S-box result");
        Console.WriteLine($"L(i-1)       = {BitUtils.GroupBits(leftBits)}");
        Console.WriteLine($"S-box output  = {BitUtils.GroupBits(sboxBits)}");
        Console.WriteLine($"P(S-box)      = {BitUtils.GroupBits(pOutput)}");
        Console.WriteLine($"Ri            = {BitUtils.GroupBits(ri)}");
        Console.WriteLine();
    }

    private static void RunSingleSBoxTask()
    {
        var input48 = ReadBits("Enter Ki XOR E(Ri-1) as 48 bits, hex, or R for random: ", 48);
        var round = ReadSBoxIndex();
        var trace = DesRoundFunction.ApplySBoxes(input48);
        var box = trace.Boxes[round - 1];

        Console.WriteLine("Task 2.9 - Sj(Bj) for a given j");
        Console.WriteLine($"Input 48 bits = {BitUtils.GroupBits(trace.InputBits, 6)}");
        Console.WriteLine($"S{round}(B{round}) = {box.OutputBits}");
        Console.WriteLine($"row={box.RowBits} ({box.Row}), column={box.ColumnBits} ({box.Column}), value={box.Value}");
        Console.WriteLine();
    }

    private static void RunRiFromSBoxesTask()
    {
        var leftBits = ReadBits("Enter L(i-1) (32 bits, hex, or R for random): ", 32);
        var sboxBits = ReadBits("Enter S1(B1)..S8(B8) as 32 bits, hex, or R for random: ", 32);
        var ri = DesRoundFunction.ComputeRightHalf(leftBits, sboxBits);
        var pOutput = DesRoundFunction.ApplyPermutationP(sboxBits);

        Console.WriteLine("Task 2.10 - Ri from S-box outputs and L(i-1)");
        Console.WriteLine($"L(i-1)      = {BitUtils.GroupBits(leftBits)}");
        Console.WriteLine($"S-box output = {BitUtils.GroupBits(sboxBits)}");
        Console.WriteLine($"P(S-box)     = {BitUtils.GroupBits(pOutput)}");
        Console.WriteLine($"Ri           = {BitUtils.GroupBits(ri)}");
        Console.WriteLine();
    }

    private static void RunCiphertextTask()
    {
        var l16 = ReadBits("Enter L16 (32 bits, hex, or R for random): ", 32);
        var r16 = ReadBits("Enter R16 (32 bits, hex, or R for random): ", 32);
        var (preoutput, cipherBits, cipherHex) = DesFinalBlock.ReconstructCiphertext(l16, r16);

        Console.WriteLine("Task 2.11 - Ciphertext from L16 and R16");
        Console.WriteLine($"L16          = {BitUtils.GroupBits(l16)}");
        Console.WriteLine($"R16          = {BitUtils.GroupBits(r16)}");
        Console.WriteLine($"R16||L16     = {BitUtils.GroupBits(preoutput)}");
        Console.WriteLine($"Cipher bits   = {BitUtils.GroupBits(cipherBits)}");
        Console.WriteLine($"Cipher hex    = {cipherHex}");
        Console.WriteLine();
    }

    private static void PrintKeyTrace(KeyScheduleTrace trace, bool includeRounds, int maxRound = 16)
    {
        Console.WriteLine($"Input key bits  = {BitUtils.GroupBits(trace.KeyBits)}");
        Console.WriteLine($"K+ bits         = {BitUtils.GroupBits(trace.KeyPlusBits)}");
        Console.WriteLine($"C0              = {BitUtils.GroupBits(trace.C0)}");
        Console.WriteLine($"D0              = {BitUtils.GroupBits(trace.D0)}");

        if (!includeRounds)
        {
            return;
        }

        foreach (var round in trace.Rounds.Take(maxRound))
        {
            Console.WriteLine($"Round {round.Round}, shift {round.Shift}");
            Console.WriteLine($"C{round.Round} = {BitUtils.GroupBits(round.C)}");
            Console.WriteLine($"D{round.Round} = {BitUtils.GroupBits(round.D)}");
            Console.WriteLine($"K{round.Round} = {BitUtils.GroupBits(round.KeyBits)}");
            Console.WriteLine($"K{round.Round} (hex) = {round.KeyHex}");
        }
    }

    private static string ReadKeyBits()
    {
        while (true)
        {
            Console.Write("Enter an 8-character key or type R for random: ");
            var input = Console.ReadLine()?.Trim();
            if (string.IsNullOrWhiteSpace(input))
            {
                continue;
            }

            if (input.Equals("R", StringComparison.OrdinalIgnoreCase))
            {
                var random = new Random();
                var key = BitUtils.RandomHex(16, random);
                Console.WriteLine($"Random key = {key}");
                return BitUtils.HexToBits(key);
            }

            if (input.Length == 8)
            {
                return BitUtils.AsciiToBits(input);
            }

            if (input.Length == 16 && BitUtils.IsHex(input))
            {
                return BitUtils.HexToBits(BitUtils.NormalizeHex(input, 16));
            }

            Console.WriteLine("Invalid input. Enter 8 characters or 16 hex digits.");
        }
    }

    private static string ReadMessageBits()
    {
        while (true)
        {
            Console.Write("Enter an 8-character message or type R for random: ");
            var input = Console.ReadLine()?.Trim();
            if (string.IsNullOrWhiteSpace(input))
            {
                continue;
            }

            if (input.Equals("R", StringComparison.OrdinalIgnoreCase))
            {
                var random = new Random();
                var message = BitUtils.RandomHex(16, random);
                Console.WriteLine($"Random message seed = {message}");
                return BitUtils.HexToBits(message);
            }

            if (input.Length == 8)
            {
                return BitUtils.AsciiToBits(input);
            }

            if (input.Length == 16 && BitUtils.IsHex(input))
            {
                return BitUtils.HexToBits(BitUtils.NormalizeHex(input, 16));
            }

            Console.WriteLine("Invalid input. Enter 8 characters or 16 hex digits.");
        }
    }

    private static string ReadBits(string prompt, int expectedLength)
    {
        while (true)
        {
            Console.Write(prompt);
            var input = Console.ReadLine()?.Trim();
            if (string.IsNullOrWhiteSpace(input))
            {
                continue;
            }

            if (input.Equals("R", StringComparison.OrdinalIgnoreCase))
            {
                var random = new Random();
                var hexChars = expectedLength / 4;
                var hex = BitUtils.RandomHex(hexChars, random);
                Console.WriteLine($"Random hex = {hex}");
                return BitUtils.HexToBits(hex);
            }

            if (input.Length == expectedLength && input.All(c => c is '0' or '1'))
            {
                return input;
            }

            if (input.Length == expectedLength / 4 && BitUtils.IsHex(input))
            {
                return BitUtils.HexToBits(BitUtils.NormalizeHex(input, expectedLength / 4));
            }

            Console.WriteLine($"Invalid input. Enter {expectedLength} bits or {expectedLength / 4} hex digits.");
        }
    }

    private static int ReadRoundNumber()
    {
        while (true)
        {
            Console.Write("Enter round number (0-16): ");
            if (int.TryParse(Console.ReadLine(), out var round) && round is >= 0 and <= 16)
            {
                return round;
            }

            Console.WriteLine("Invalid round.");
        }
    }

    private static int ReadSBoxIndex()
    {
        while (true)
        {
            Console.Write("Enter S-box index (1-8): ");
            if (int.TryParse(Console.ReadLine(), out var index) && index is >= 1 and <= 8)
            {
                return index;
            }

            Console.WriteLine("Invalid S-box.");
        }
    }
}
