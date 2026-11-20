namespace Lab5.PKI_and_DSA;

/// <summary>
/// Main entry point for the PKI and DSA laboratory tool.
/// Parses command-line arguments, initializes the PKI service, and executes the requested operation.
/// </summary>
internal static class Program
{
    /// <summary>
    /// Asynchronous main entry point.
    /// Handles CLI command parsing, service initialization, and result output.
    /// </summary>
    /// <param name="args">Command-line arguments passed by the user.</param>
    /// <returns>Exit code: 0 for success, 1 for failure.</returns>
    private static async Task<int> Main(string[] args)
    {
        try
        {
            // Parse the command-line arguments into a structured command object
            var command = CliParser.Parse(args);
            if (command.Kind == PkiCommandKind.Help)
            {
                CliParser.PrintHelp(Console.Out);
                return 0;
            }

            // Initialize the PKI environment and service
            var projectDirectory = GetProjectDirectory();
            var environment = PkiEnvironment.Create(projectDirectory);
            var runner = new OpenSslRunner(environment);
            var service = new PkiService(environment, PkiPolicy.Default, runner);

            // Dispatch the parsed command to the appropriate service method
            var result = command.Kind switch
            {
                PkiCommandKind.InitCa => await service.InitializeCaAsync(command.Subject ?? new SubjectName("Lab5 Root CA")),
                PkiCommandKind.IssueUser => await service.IssueUserCertificateAsync(command.UserName!, command.Subject ?? new SubjectName(command.UserName!)),
                PkiCommandKind.RevokeUser => await service.RevokeUserCertificateAsync(command.UserName!),
                PkiCommandKind.SignFile => await service.SignFileAsync(command.UserName!, command.FilePath!),
                PkiCommandKind.VerifySignature => await service.VerifySignatureAsync(command.UserName!, command.FilePath!),
                _ => PkiOperationResult.Fail("Unsupported command.")
            };

            // Output the result to console and return appropriate exit code
            if (result.Success)
            {
                Console.WriteLine(result.Message);
                if (!string.IsNullOrWhiteSpace(result.ArtifactPath))
                {
                    Console.WriteLine($"Artifact: {result.ArtifactPath}");
                }

                return 0;
            }

            Console.Error.WriteLine(result.Message);
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    /// <summary>
    /// Gets the project directory path, calculated relative to the application base directory.
    /// Assumes the executable is in bin\Debug\net10.0 and navigates up three levels to reach the project root.
    /// </summary>
    private static string GetProjectDirectory()
        => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
}
