using System.Diagnostics;

namespace Lab5.PKI_and_DSA;

/// <summary>
/// Wrapper for executing OpenSSL commands asynchronously.
/// Handles process creation, output redirection, and error reporting.
/// </summary>
internal sealed class OpenSslRunner
{
    private readonly PkiEnvironment _environment;

    /// <summary>
    /// Initializes a new instance of the OpenSSlRunner class.
    /// </summary>
    /// <param name="environment">The PKI environment configuration containing the OpenSSL executable path.</param>
    public OpenSslRunner(PkiEnvironment environment)
    {
        _environment = environment;
    }

    /// <summary>
    /// Executes an OpenSSL command asynchronously and returns a structured result.
    /// </summary>
    /// <param name="arguments">The OpenSSL command arguments (e.g., "genpkey", "-algorithm", "RSA").</param>
    /// <param name="workingDirectory">The working directory for the OpenSSL process.</param>
    /// <param name="successMessage">The message to include in the result if the command succeeds.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A PkiOperationResult indicating success or failure with associated messages.</returns>
    public async Task<PkiOperationResult> RunAsync(IEnumerable<string> arguments, string workingDirectory, string successMessage, CancellationToken cancellationToken = default)
    {
        // Configure the process to run OpenSSL with captured output
        var startInfo = new ProcessStartInfo
        {
            FileName = _environment.OpenSslExecutable,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        // Add all arguments to the process
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        // Start the process and capture output asynchronously
        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        // Wait for the process to complete and capture output
        await process.WaitForExitAsync(cancellationToken);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        // Check for errors and return appropriate result
        if (process.ExitCode != 0)
        {
            var error = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            return PkiOperationResult.Fail($"OpenSSL failed with exit code {process.ExitCode}: {error.Trim()}");
        }

        // Append stdout to the success message if present
        var message = successMessage;
        if (!string.IsNullOrWhiteSpace(stdout))
        {
            message = string.Concat(message, Environment.NewLine, stdout.Trim());
        }

        return PkiOperationResult.Ok(message);
    }

    /// <summary>
    /// Executes an OpenSSL command and returns the raw stdout output.
    /// Throws an exception if the command fails.
    /// Used for capturing structured output like certificate data.
    /// </summary>
    /// <param name="arguments">The OpenSSL command arguments.</param>
    /// <param name="workingDirectory">The working directory for the OpenSSL process.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>The raw standard output from the OpenSSL command.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the OpenSSL command fails.</exception>
    public async Task<string> RunCaptureAsync(IEnumerable<string> arguments, string workingDirectory, CancellationToken cancellationToken = default)
    {
        // Configure the process to run OpenSSL with captured output
        var startInfo = new ProcessStartInfo
        {
            FileName = _environment.OpenSslExecutable,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        // Add all arguments to the process
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        // Start the process and capture output asynchronously
        using var process = new Process { StartInfo = startInfo };
        process.Start();

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        // Wait for the process to complete and capture output
        await process.WaitForExitAsync(cancellationToken);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        // Throw if the command failed; return stdout otherwise
        if (process.ExitCode != 0)
        {
            var error = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            throw new InvalidOperationException($"OpenSSL failed with exit code {process.ExitCode}: {error.Trim()}");
        }

        return stdout;
    }
}
