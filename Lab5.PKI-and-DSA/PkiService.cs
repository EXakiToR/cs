using System.Security.Cryptography.X509Certificates;

namespace Lab5.PKI_and_DSA;

/// <summary>
/// Service for managing PKI operations including CA initialization, certificate issuance,
/// revocation, and digital signature creation/verification.
/// Acts as the main interface between CLI and OpenSSL command execution.
/// </summary>
internal sealed class PkiService
{
    private readonly PkiEnvironment _environment;
    private readonly PkiPolicy _policy;
    private readonly OpenSslRunner _runner;

    /// <summary>
    /// Initializes a new instance of the PkiService class.
    /// </summary>
    /// <param name="environment">Configuration for the PKI environment and directories.</param>
    /// <param name="policy">PKI policy defining key sizes and certificate validity periods.</param>
    /// <param name="runner">OpenSSL runner for executing cryptographic commands.</param>
    public PkiService(PkiEnvironment environment, PkiPolicy policy, OpenSslRunner runner)
    {
        _environment = environment;
        _policy = policy;
        _runner = runner;
    }

    /// <summary>
    /// Initializes an internal Certificate Authority (CA).
    /// Creates a 4096-bit RSA private key and a self-signed certificate valid for 10 years.
    /// Sets up the directory structure and OpenSSL configuration file for certificate operations.
    /// </summary>
    /// <param name="caSubject">The subject name for the CA certificate (CN, O, etc.).</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A PkiOperationResult indicating success and providing the CA certificate path.</returns>
    public async Task<PkiOperationResult> InitializeCaAsync(SubjectName caSubject, CancellationToken cancellationToken = default)
    {
        // Ensure all required PKI directories exist
        EnsureDirectories();
        // Write the OpenSSL configuration file for CA operations
        await WriteOpenSslConfigAsync(cancellationToken);

        // Generate CA private key if it doesn't already exist
        if (!File.Exists(_environment.Paths.CaKey))
        {
            var keyResult = await _runner.RunAsync(
                new[] { "genpkey", "-algorithm", "RSA", "-pkeyopt", $"rsa_keygen_bits:{_policy.CaKeySize}", "-out", _environment.Paths.CaKey },
                _environment.PkiRootDirectory,
                "CA private key generated.",
                cancellationToken);

            if (!keyResult.Success)
            {
                return keyResult;
            }
        }

        // Generate self-signed CA certificate if it doesn't already exist
        if (!File.Exists(_environment.Paths.CaCertificate))
        {
            var certResult = await _runner.RunAsync(
                new[]
                {
                    "req", "-x509", "-new", "-key", _environment.Paths.CaKey,
                    "-sha256", "-days", _policy.CaValidityDays.ToString(),
                    "-out", _environment.Paths.CaCertificate,
                    "-subj", caSubject.ToOpenSslDistinguishedName(),
                    // Extensions marking this as a CA certificate with limited depth
                    "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                    "-addext", "subjectKeyIdentifier=hash"
                },
                _environment.PkiRootDirectory,
                "CA certificate created.",
                cancellationToken);

            if (!certResult.Success)
            {
                return certResult;
            }
        }

        // Create the certificate chain file (initially contains only the CA certificate)
        await File.WriteAllTextAsync(_environment.Paths.CaChain, await File.ReadAllTextAsync(_environment.Paths.CaCertificate, cancellationToken), cancellationToken);
        var crlResult = await GenerateCrlAsync(cancellationToken);
        if (!crlResult.Success)
        {
            return crlResult;
        }
        return PkiOperationResult.Ok($"Internal CA is ready in '{_environment.PkiRootDirectory}'.", _environment.Paths.CaCertificate);
    }

    /// <summary>
    /// Issues a new certificate for a user.
    /// Generates a 2048-bit RSA private key, creates a certificate signing request (CSR),
    /// and signs it with the CA key to produce a user certificate valid for 365 days.
    /// </summary>
    /// <param name="userName">The username for which to issue a certificate.</param>
    /// <param name="subject">The subject name for the user certificate (CN, O, etc.).</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A PkiOperationResult indicating success and providing the certificate path, or failure reason.</returns>
    public async Task<PkiOperationResult> IssueUserCertificateAsync(string userName, SubjectName subject, CancellationToken cancellationToken = default)
    {
        // Verify that the CA is initialized and ready
        ValidateReadyForIssue();

        var keyPath = _environment.Paths.UserPrivateKey(userName);
        var csrPath = _environment.Paths.UserRequest(userName);
        var certPath = _environment.Paths.UserCertificate(userName);

        // Prevent overwriting existing certificates
        if (File.Exists(certPath))
        {
            if (!IsCertificateRevoked(certPath))
            {
                return PkiOperationResult.Fail($"Certificate already exists for '{userName}'. Revoke it before issuing a new one.");
            }

            // Preserve every revoked certificate before replacing the active identity.
            var archivePath = Path.Combine(_environment.Paths.Revoked, $"{userName}.{Guid.NewGuid():N}.cert.pem");
            File.Move(certPath, archivePath);
        }

        // Step 1: Generate the user's private key (2048-bit RSA)
        var keyResult = await _runner.RunAsync(
            new[] { "genpkey", "-algorithm", "RSA", "-pkeyopt", $"rsa_keygen_bits:{_policy.UserKeySize}", "-out", keyPath },
            _environment.PkiRootDirectory,
            $"User private key generated for '{userName}'.",
            cancellationToken);

        if (!keyResult.Success)
        {
            return keyResult;
        }

        // Step 2: Create a certificate signing request (CSR) from the private key and subject
        var requestResult = await _runner.RunAsync(
            new[]
            {
                "req", "-new", "-key", keyPath, "-out", csrPath,
                "-subj", subject.ToOpenSslDistinguishedName()
            },
            _environment.PkiRootDirectory,
            $"CSR created for '{userName}'.",
            cancellationToken);

        if (!requestResult.Success)
        {
            return requestResult;
        }

        // Step 3: Sign the CSR with the CA key to produce the user certificate
        var signResult = await _runner.RunAsync(
            new[]
            {
                "ca", "-batch", "-config", _environment.Paths.OpenSslConfig,
                "-extensions", "usr_cert",
                "-days", _policy.UserValidityDays.ToString(),
                "-notext", "-md", "sha256",
                "-in", csrPath,
                "-out", certPath
            },
            _environment.PkiRootDirectory,
            $"User certificate issued for '{userName}'.",
            cancellationToken);

        if (!signResult.Success)
        {
            return signResult;
        }

        return PkiOperationResult.Ok($"User certificate issued for '{userName}'.", certPath);
    }

    /// <summary>
    /// Revokes a user's certificate by adding it to the revocation list.
    /// Also regenerates the Certificate Revocation List (CRL) so that signature verification
    /// can check if the certificate has been revoked.
    /// </summary>
    /// <param name="userName">The username whose certificate should be revoked.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A PkiOperationResult indicating success and providing the CRL path, or failure reason.</returns>
    public async Task<PkiOperationResult> RevokeUserCertificateAsync(string userName, CancellationToken cancellationToken = default)
    {
        // Verify that the CA is initialized and ready
        ValidateReadyForIssue();

        var certPath = _environment.Paths.UserCertificate(userName);
        if (!File.Exists(certPath))
        {
            return PkiOperationResult.Fail($"Certificate not found for '{userName}'.");
        }

        // Revoke the certificate by marking it in the CA database
        var revokeResult = IsCertificateRevoked(certPath) ? PkiOperationResult.Ok("Certificate already revoked.") : await _runner.RunAsync(
            new[]
            {
                "ca", "-config", _environment.Paths.OpenSslConfig,
                "-revoke", certPath
            },
            _environment.PkiRootDirectory,
            $"Certificate revoked for '{userName}'.",
            cancellationToken);

        if (!revokeResult.Success)
        {
            return revokeResult;
        }

        // Regenerate the Certificate Revocation List (CRL) to include the revoked certificate
        var crlPath = _environment.Paths.CrlPath();
        // A stale CRL must not remain usable if regeneration fails.
        File.Delete(crlPath);
        var genCrlResult = await GenerateCrlAsync(cancellationToken);

        if (!genCrlResult.Success)
        {
            return genCrlResult;
        }

        return PkiOperationResult.Ok($"Certificate revoked for '{userName}'.", crlPath);
    }

    /// <summary>
    /// Creates a digital signature for a file using the user's private key.
    /// The signature is stored as a separate file with .sig extension.
    /// Uses SHA256 hash algorithm for the signature.
    /// </summary>
    /// <param name="userName">The username whose private key to use for signing.</param>
    /// <param name="filePath">The path to the file to sign.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A PkiOperationResult indicating success and providing the signature file path, or failure reason.</returns>
    public async Task<PkiOperationResult> SignFileAsync(string userName, string filePath, CancellationToken cancellationToken = default)
    {
        filePath = Path.GetFullPath(filePath);
        var keyPath = _environment.Paths.UserPrivateKey(userName);
        if (!File.Exists(keyPath))
        {
            return PkiOperationResult.Fail($"Private key not found for '{userName}'.");
        }

        if (!File.Exists(filePath))
        {
            return PkiOperationResult.Fail($"File '{filePath}' was not found.");
        }

        var certificateCheck = await VerifyCertificateAsync(_environment.Paths.UserCertificate(userName), cancellationToken);
        if (!certificateCheck.Success)
        {
            return certificateCheck;
        }

        // Create a SHA256 digital signature of the file using the user's private key
        var signaturePath = _environment.Paths.Signature(filePath);
        var result = await _runner.RunAsync(
            new[] { "dgst", "-sha256", "-sign", keyPath, "-out", signaturePath, filePath },
            Path.GetDirectoryName(Path.GetFullPath(filePath)) ?? _environment.PkiRootDirectory,
            $"Signature created at '{signaturePath}'.",
            cancellationToken);

        return result.Success ? PkiOperationResult.Ok($"Signature created for '{filePath}'.", signaturePath) : result;
    }

    /// <summary>
    /// Verifies a file's digital signature using the signer's certificate.
    /// Checks that the signature is valid and that the certificate is not revoked.
    /// Also performs certificate chain verification using the CA certificate.
    /// </summary>
    /// <param name="userName">The username whose certificate to use for verification.</param>
    /// <param name="filePath">The path to the file whose signature to verify.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A PkiOperationResult indicating whether the signature is valid, or failure reason.</returns>
    public async Task<PkiOperationResult> VerifySignatureAsync(string userName, string filePath, CancellationToken cancellationToken = default)
    {
        filePath = Path.GetFullPath(filePath);
        var certPath = _environment.Paths.UserCertificate(userName);
        if (!File.Exists(certPath))
        {
            return PkiOperationResult.Fail($"Certificate not found for '{userName}'.");
        }

        if (!File.Exists(filePath))
        {
            return PkiOperationResult.Fail($"File '{filePath}' was not found.");
        }

        var signaturePath = _environment.Paths.Signature(filePath);
        if (!File.Exists(signaturePath))
        {
            return PkiOperationResult.Fail($"Signature file '{signaturePath}' was not found.");
        }

        // First, verify that the certificate is valid and not revoked
        var certificateCheck = await VerifyCertificateAsync(certPath, cancellationToken);
        if (!certificateCheck.Success)
        {
            return certificateCheck;
        }

        // Extract the public key from the certificate for signature verification
        var publicKeyPath = Path.Combine(_environment.PkiRootDirectory, $"{Guid.NewGuid():N}.pub.pem");
        try
        {
            // Extract public key from the certificate
            var publicKeyPem = await _runner.RunCaptureAsync(new[] { "x509", "-pubkey", "-noout", "-in", certPath }, _environment.PkiRootDirectory, cancellationToken);
            await File.WriteAllTextAsync(publicKeyPath, publicKeyPem, cancellationToken);

            // Verify the signature using the public key
            var verifyResult = await _runner.RunAsync(
                new[] { "dgst", "-sha256", "-verify", publicKeyPath, "-signature", signaturePath, filePath },
                Path.GetDirectoryName(Path.GetFullPath(filePath)) ?? _environment.PkiRootDirectory,
                $"Signature verified successfully for '{filePath}'.",
                cancellationToken);

            if (!verifyResult.Success)
            {
                return verifyResult;
            }

            return PkiOperationResult.Ok($"Signature verified successfully for '{filePath}'.");
        }
        finally
        {
            // Clean up the temporary public key file
            if (File.Exists(publicKeyPath))
            {
                File.Delete(publicKeyPath);
            }
        }
    }

    /// <summary>
    /// Verifies that a certificate is valid and not revoked.
    /// Checks the certificate chain against the CA certificate.
    /// Requires a CRL (Certificate Revocation List) to check revocation.
    /// </summary>
    /// <param name="certPath">The path to the certificate to verify.</param>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    /// <returns>A PkiOperationResult indicating whether the certificate is valid.</returns>
    private async Task<PkiOperationResult> VerifyCertificateAsync(string certPath, CancellationToken cancellationToken)
    {
        var verifyArgs = new List<string>
        {
            "verify", "-CAfile", _environment.Paths.CaCertificate
        };

        // Never silently disable revocation checking.
        var crlPath = _environment.Paths.CrlPath();
        if (!File.Exists(crlPath))
        {
            return PkiOperationResult.Fail("The CRL is missing. Run init-ca to regenerate it before signing or verifying.");
        }

        verifyArgs.AddRange(new[] { "-crl_check", "-CRLfile", crlPath });

        verifyArgs.Add(certPath);

        var result = await _runner.RunAsync(
            verifyArgs,
            _environment.PkiRootDirectory,
            $"Certificate verified for '{Path.GetFileNameWithoutExtension(certPath)}'.",
            cancellationToken);

        return result.Success ? PkiOperationResult.Ok($"Certificate verified for '{Path.GetFileNameWithoutExtension(certPath)}'.") : result;
    }

    /// <summary>
    /// Ensures all required PKI directories exist, creating them if necessary.
    /// </summary>
    private void EnsureDirectories()
    {
        Directory.CreateDirectory(_environment.PkiRootDirectory);
        Directory.CreateDirectory(_environment.Paths.Private);
        Directory.CreateDirectory(_environment.Paths.Certificates);
        Directory.CreateDirectory(_environment.Paths.NewCertificates);
        Directory.CreateDirectory(_environment.Paths.Requests);
        Directory.CreateDirectory(_environment.Paths.Revoked);
        Directory.CreateDirectory(_environment.Paths.Crl);
    }

    /// <summary>
    /// Writes the OpenSSL configuration file needed for CA operations.
    /// Also initializes the CA database files (index.txt, serial, crlnumber) if they don't exist.
    /// </summary>
    /// <param name="cancellationToken">Optional cancellation token.</param>
    private async Task WriteOpenSslConfigAsync(CancellationToken cancellationToken)
    {
        var config = BuildOpenSslConfig();
        await File.WriteAllTextAsync(_environment.Paths.OpenSslConfig, config, cancellationToken);

        // Initialize CA database index file if it doesn't exist
        if (!File.Exists(_environment.Paths.Database))
        {
            await File.WriteAllTextAsync(_environment.Paths.Database, string.Empty, cancellationToken);
        }

        // Initialize serial number file if it doesn't exist (starts at 1000)
        if (!File.Exists(_environment.Paths.Serial))
        {
            await File.WriteAllTextAsync(_environment.Paths.Serial, "1000", cancellationToken);
        }

        // Initialize CRL number file if it doesn't exist (starts at 1000)
        if (!File.Exists(_environment.Paths.CrlNumber))
        {
            await File.WriteAllTextAsync(_environment.Paths.CrlNumber, "1000", cancellationToken);
        }
    }

    /// <summary>
    /// Builds the OpenSSL configuration file content.
    /// This configuration defines the CA defaults, certificate policies, and extensions.
    /// </summary>
    /// <returns>The OpenSSL configuration file content as a string.</returns>
    private string BuildOpenSslConfig()
    {
        var dir = NormalizePath(_environment.PkiRootDirectory).Replace("$", "\\$").Replace("\"", "\\\"");
        return $"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = "{dir}"
certs = $dir/certs
new_certs_dir = $dir/newcerts
database = $dir/index.txt
serial = $dir/serial
crlnumber = $dir/crlnumber
crl_dir = $dir/crl
certificate = $dir/certs/ca.cert.pem
private_key = $dir/private/ca.key.pem
crl = $dir/crl/ca.crl.pem
default_md = sha256
policy = policy_loose
copy_extensions = none
unique_subject = no
default_days = {_policy.UserValidityDays}
default_crl_days = 30
x509_extensions = usr_cert

[ policy_loose ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ usr_cert ]
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,emailProtection
""";
    }

    /// <summary>
    /// Validates that the CA is initialized before performing certificate operations.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if the CA is not initialized.</exception>
    private void ValidateReadyForIssue()
    {
        if (!File.Exists(_environment.Paths.CaKey) || !File.Exists(_environment.Paths.CaCertificate))
        {
            throw new InvalidOperationException("The CA is not initialized. Run CA initialization first.");
        }
    }

    private bool IsCertificateRevoked(string certPath)
    {
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(certPath);
        var serial = certificate.SerialNumber.TrimStart('0');
        return File.ReadLines(_environment.Paths.Database)
            .Select(line => line.Split('\t'))
            .Any(fields => fields.Length >= 4 && fields[0] == "R" &&
                fields[3].TrimStart('0').Equals(serial, StringComparison.OrdinalIgnoreCase));
    }

    private async Task<PkiOperationResult> GenerateCrlAsync(CancellationToken cancellationToken)
    {
        var crlPath = _environment.Paths.CrlPath();
        var temporaryPath = crlPath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            var result = await _runner.RunAsync(
                new[] { "ca", "-config", _environment.Paths.OpenSslConfig, "-gencrl", "-out", temporaryPath },
                _environment.PkiRootDirectory, "CRL updated.", cancellationToken);
            if (result.Success)
            {
                File.Move(temporaryPath, crlPath, overwrite: true);
            }

            return result;
        }
        finally
        {
            File.Delete(temporaryPath);
        }
    }

    /// <summary>
    /// Normalizes a Windows path to use forward slashes, which OpenSSL prefers.
    /// </summary>
    /// <param name="path">The path to normalize.</param>
    /// <returns>The normalized path with forward slashes.</returns>
    private static string NormalizePath(string path) => Path.GetFullPath(path).Replace('\\', '/');
}

/// <summary>
/// Extension methods for PkiPaths to provide additional convenience methods.
/// </summary>
internal static class PkiPathsExtensions
{
    /// <summary>
    /// Gets the path to the Certificate Revocation List (CRL) file.
    /// </summary>
    /// <param name="paths">The PkiPaths instance.</param>
    /// <returns>The full path to the CRL file.</returns>
    public static string CrlPath(this PkiPaths paths) => Path.Combine(paths.Crl, "ca.crl.pem");
}
