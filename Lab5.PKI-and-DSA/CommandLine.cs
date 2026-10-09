namespace Lab5.PKI_and_DSA;

internal enum PkiCommandKind
{
    Help,
    InitCa,
    IssueUser,
    RevokeUser,
    SignFile,
    VerifySignature
}

internal sealed record CliCommand(
    PkiCommandKind Kind,
    string? UserName = null,
    string? FilePath = null,
    SubjectName? Subject = null);

internal static class CliParser
{
    public static CliCommand Parse(string[] args)
    {
        if (args.Length == 0)
        {
            return new CliCommand(PkiCommandKind.Help);
        }

        var command = args[0].ToLowerInvariant();
        var tail = args.Skip(1).ToArray();

        return command switch
        {
            "init-ca" => new CliCommand(PkiCommandKind.InitCa, Subject: BuildSubject(tail, "Lab5 Root CA")),
            "issue-user" => ParseUserCommand(PkiCommandKind.IssueUser, tail, defaultCommonName: null),
            "revoke-user" => ParseNamedUserCommand(PkiCommandKind.RevokeUser, tail),
            "sign" => ParseFileCommand(PkiCommandKind.SignFile, tail),
            "verify" => ParseFileCommand(PkiCommandKind.VerifySignature, tail),
            "help" or "-h" or "--help" or "/?" => new CliCommand(PkiCommandKind.Help),
            _ => throw new ArgumentException($"Unknown command '{args[0]}'.")
        };
    }

    public static void PrintHelp(TextWriter writer)
    {
        writer.WriteLine("Lab 5 - PKI and DSA");
        writer.WriteLine();
        writer.WriteLine("Commands:");
        writer.WriteLine("  init-ca [--cn value] [--o value] [--ou value] [--c value] [--email value]");
        writer.WriteLine("  issue-user <userName> [--cn value] [--o value] [--ou value] [--c value] [--email value]");
        writer.WriteLine("  revoke-user <userName>");
        writer.WriteLine("  sign <userName> <filePath>");
        writer.WriteLine("  verify <userName> <filePath>");
        writer.WriteLine();
        writer.WriteLine("Notes:");
        writer.WriteLine("  - CA keys use RSA-4096 and self-signed certificates are valid for 3650 days.");
        writer.WriteLine("  - User keys use RSA-2048 and issued certificates are valid for 365 days.");
    }

    private static CliCommand ParseUserCommand(PkiCommandKind kind, string[] args, string? defaultCommonName)
    {
        var options = ParseOptions(args, out var positional);
        if (positional.Count < 1)
        {
            throw new ArgumentException("A user name is required.");
        }

        var userName = positional[0];
        var subject = BuildSubject(options, defaultCommonName ?? userName);
        return new CliCommand(kind, UserName: userName, Subject: subject);
    }

    private static CliCommand ParseNamedUserCommand(PkiCommandKind kind, string[] args)
    {
        var options = ParseOptions(args, out var positional);
        if (positional.Count < 1)
        {
            throw new ArgumentException("A user name is required.");
        }

        return new CliCommand(kind, UserName: positional[0]);
    }

    private static CliCommand ParseFileCommand(PkiCommandKind kind, string[] args)
    {
        var options = ParseOptions(args, out var positional);
        if (positional.Count < 2)
        {
            throw new ArgumentException("A user name and file path are required.");
        }

        return new CliCommand(kind, UserName: positional[0], FilePath: positional[1]);
    }

    private static SubjectName BuildSubject(string[] args, string defaultCommonName)
    {
        var options = ParseOptions(args, out _);
        return BuildSubject(options, defaultCommonName);
    }

    private static SubjectName BuildSubject(Dictionary<string, string> options, string defaultCommonName)
    {
        var commonName = GetOption(options, "cn") ?? defaultCommonName;
        return new SubjectName(
            commonName,
            GetOption(options, "c"),
            GetOption(options, "o"),
            GetOption(options, "ou"),
            GetOption(options, "email"));
    }

    private static Dictionary<string, string> ParseOptions(string[] args, out List<string> positional)
    {
        positional = new List<string>();
        var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (var index = 0; index < args.Length; index++)
        {
            var token = args[index];
            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                positional.Add(token);
                continue;
            }

            var option = token[2..];
            string name;
            string value;

            var equalsIndex = option.IndexOf('=');
            if (equalsIndex >= 0)
            {
                name = option[..equalsIndex];
                value = option[(equalsIndex + 1)..];
            }
            else
            {
                name = option;
                if (index + 1 >= args.Length)
                {
                    throw new ArgumentException($"Missing value for option '--{name}'.");
                }

                value = args[++index];
            }

            options[name] = value;
        }

        return options;
    }

    private static string? GetOption(Dictionary<string, string> options, string name)
        => options.TryGetValue(name, out var value) ? value : null;
}
