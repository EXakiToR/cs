namespace Lab5.PKI_and_DSA;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            var command = CliParser.Parse(args);
            if (command.Kind == PkiCommandKind.Help)
            {
                CliParser.PrintHelp(Console.Out);
                return 0;
            }

            var projectDirectory = GetProjectDirectory();
            var environment = PkiEnvironment.Create(projectDirectory);
            var runner = new OpenSslRunner(environment);
            var service = new PkiService(environment, PkiPolicy.Default, runner);

            var result = command.Kind switch
            {
                PkiCommandKind.InitCa => await service.InitializeCaAsync(command.Subject ?? new SubjectName("Lab5 Root CA")),
                PkiCommandKind.IssueUser => await service.IssueUserCertificateAsync(command.UserName!, command.Subject ?? new SubjectName(command.UserName!)),
                PkiCommandKind.RevokeUser => await service.RevokeUserCertificateAsync(command.UserName!),
                PkiCommandKind.SignFile => await service.SignFileAsync(command.UserName!, command.FilePath!),
                PkiCommandKind.VerifySignature => await service.VerifySignatureAsync(command.UserName!, command.FilePath!),
                _ => PkiOperationResult.Fail("Unsupported command.")
            };

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

    private static string GetProjectDirectory()
        => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
}
