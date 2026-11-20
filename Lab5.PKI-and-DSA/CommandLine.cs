namespace Lab5.PKI_and_DSA;

/// <summary>Lists the operations supported by the PKI command-line tool.</summary>
internal enum PkiCommandKind
{
    Help,
    InitCa,
    IssueUser,
    RevokeUser,
    SignFile,
    VerifySignature
}

/// <summary>
/// Stores a parsed command for Program to dispatch to PkiService.
/// Fields that do not apply to the selected operation remain null.
/// </summary>
/// <param name="Kind">The operation to execute.</param>
/// <param name="UserName">The user whose certificate or key is involved.</param>
/// <param name="FilePath">The file to sign or verify.</param>
/// <param name="Subject">The certificate subject used when initializing the CA or issuing a certificate.</param>
internal sealed record CliCommand(
    PkiCommandKind Kind,
    string? UserName = null,
    string? FilePath = null,
    SubjectName? Subject = null);

/// <summary>
/// Converts command-line arguments into commands and prints usage information.
/// Cryptographic operations and user-name validation are handled by the PKI layer.
/// </summary>
internal static class CliParser
{
    /// <summary>Parses the command name, positional arguments, and certificate subject options.</summary>
    /// <param name="args">Arguments supplied to the application, excluding its executable name.</param>
    /// <returns>A command ready for dispatch, or Help when no arguments are supplied.</returns>
    /// <exception cref="ArgumentException">The command is unknown or a required argument or option value is missing.</exception>
    public static CliCommand Parse(string[] args)
    {
        if (args.Length == 0)
        {
            return new CliCommand(PkiCommandKind.Help);
        }

        // Normalize only the command name; preserve case in user names, paths, and subject values.
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

    /// <summary>Writes supported commands, subject options, and the default key policy.</summary>
    /// <param name="writer">The destination for help text, normally Console.Out.</param>
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

    /// <summary>Reads a user name and optional certificate subject fields for issuance.</summary>
    private static CliCommand ParseUserCommand(PkiCommandKind kind, string[] args, string? defaultCommonName)
    {
        var options = ParseOptions(args, out var positional);
        if (positional.Count < 1)
        {
            throw new ArgumentException("A user name is required.");
        }

        var userName = positional[0];
        // If no explicit default is supplied, use the user name as the subject's common name.
        var subject = BuildSubject(options, defaultCommonName ?? userName);
        return new CliCommand(kind, UserName: userName, Subject: subject);
    }

    /// <summary>Reads the user name for an operation that needs no file or subject, such as revocation.</summary>
    private static CliCommand ParseNamedUserCommand(PkiCommandKind kind, string[] args)
    {
        var options = ParseOptions(args, out var positional);
        if (positional.Count < 1)
        {
            throw new ArgumentException("A user name is required.");
        }

        return new CliCommand(kind, UserName: positional[0]);
    }

    /// <summary>Reads the signer name followed by the file path for signing or verification.</summary>
    private static CliCommand ParseFileCommand(PkiCommandKind kind, string[] args)
    {
        var options = ParseOptions(args, out var positional);
        if (positional.Count < 2)
        {
            throw new ArgumentException("A user name and file path are required.");
        }

        return new CliCommand(kind, UserName: positional[0], FilePath: positional[1]);
    }

    /// <summary>Extracts subject options from raw arguments, using the supplied common-name fallback.</summary>
    private static SubjectName BuildSubject(string[] args, string defaultCommonName)
    {
        var options = ParseOptions(args, out _);
        return BuildSubject(options, defaultCommonName);
    }

    /// <summary>Maps CN, C, O, OU, and email options to X.509 subject fields.</summary>
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

    /// <summary>
    /// Separates positional arguments from case-insensitive options.
    /// Accepts both --name=value and --name value; later duplicate options replace earlier ones.
    /// Option names are collected here without checking whether a command supports them.
    /// </summary>
    /// <param name="args">Arguments following the command name.</param>
    /// <param name="positional">Non-option arguments in their original order.</param>
    /// <returns>A dictionary of option names without the leading two hyphens and their values.</returns>
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

            // Split on the first equals sign so additional equals signs remain part of the value.
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

                // Consume the next token as the value so it is not parsed again as a separate argument.
                value = args[++index];
            }

            options[name] = value;
        }

        return options;
    }

    /// <summary>Returns an option value, or null when the option was omitted.</summary>
    private static string? GetOption(Dictionary<string, string> options, string name)
        => options.TryGetValue(name, out var value) ? value : null;
}
