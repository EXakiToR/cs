using System.Diagnostics;

namespace Lab5.PKI_and_DSA;

internal sealed class OpenSslRunner
{
    private readonly PkiEnvironment _environment;

    public OpenSslRunner(PkiEnvironment environment)
    {
        _environment = environment;
    }

    public async Task<PkiOperationResult> RunAsync(IEnumerable<string> arguments, string workingDirectory, string successMessage, CancellationToken cancellationToken = default)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = _environment.OpenSslExecutable,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await process.WaitForExitAsync(cancellationToken);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        if (process.ExitCode != 0)
        {
            var error = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            return PkiOperationResult.Fail($"OpenSSL failed with exit code {process.ExitCode}: {error.Trim()}");
        }

        var message = successMessage;
        if (!string.IsNullOrWhiteSpace(stdout))
        {
            message = string.Concat(message, Environment.NewLine, stdout.Trim());
        }

        return PkiOperationResult.Ok(message);
    }

    public async Task<string> RunCaptureAsync(IEnumerable<string> arguments, string workingDirectory, CancellationToken cancellationToken = default)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = _environment.OpenSslExecutable,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await process.WaitForExitAsync(cancellationToken);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        if (process.ExitCode != 0)
        {
            var error = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            throw new InvalidOperationException($"OpenSSL failed with exit code {process.ExitCode}: {error.Trim()}");
        }

        return stdout;
    }
}
