namespace Lab5.PKI_and_DSA;

internal sealed class PkiService
{
    private readonly PkiEnvironment _environment;
    private readonly PkiPolicy _policy;
    private readonly OpenSslRunner _runner;

    public PkiService(PkiEnvironment environment, PkiPolicy policy, OpenSslRunner runner)
    {
        _environment = environment;
        _policy = policy;
        _runner = runner;
    }

    public async Task<PkiOperationResult> InitializeCaAsync(SubjectName caSubject, CancellationToken cancellationToken = default)
    {
        EnsureDirectories();
        await WriteOpenSslConfigAsync(cancellationToken);

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

        if (!File.Exists(_environment.Paths.CaCertificate))
        {
            var certResult = await _runner.RunAsync(
                new[]
                {
                    "req", "-x509", "-new", "-key", _environment.Paths.CaKey,
                    "-sha256", "-days", _policy.CaValidityDays.ToString(),
                    "-out", _environment.Paths.CaCertificate,
                    "-subj", caSubject.ToOpenSslDistinguishedName(),
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

        await File.WriteAllTextAsync(_environment.Paths.CaChain, await File.ReadAllTextAsync(_environment.Paths.CaCertificate, cancellationToken), cancellationToken);
        return PkiOperationResult.Ok($"Internal CA is ready in '{_environment.PkiRootDirectory}'.", _environment.Paths.CaCertificate);
    }

    public async Task<PkiOperationResult> IssueUserCertificateAsync(string userName, SubjectName subject, CancellationToken cancellationToken = default)
    {
        ValidateReadyForIssue();

        var keyPath = _environment.Paths.UserPrivateKey(userName);
        var csrPath = _environment.Paths.UserRequest(userName);
        var certPath = _environment.Paths.UserCertificate(userName);

        if (File.Exists(certPath))
        {
            return PkiOperationResult.Fail($"Certificate already exists for '{userName}'. Revoke or remove it before issuing a new one.");
        }

        var keyResult = await _runner.RunAsync(
            new[] { "genpkey", "-algorithm", "RSA", "-pkeyopt", $"rsa_keygen_bits:{_policy.UserKeySize}", "-out", keyPath },
            _environment.PkiRootDirectory,
            $"User private key generated for '{userName}'.",
            cancellationToken);

        if (!keyResult.Success)
        {
            return keyResult;
        }

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

    public async Task<PkiOperationResult> RevokeUserCertificateAsync(string userName, CancellationToken cancellationToken = default)
    {
        ValidateReadyForIssue();

        var certPath = _environment.Paths.UserCertificate(userName);
        if (!File.Exists(certPath))
        {
            return PkiOperationResult.Fail($"Certificate not found for '{userName}'.");
        }

        var revokeResult = await _runner.RunAsync(
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

        var crlPath = _environment.Paths.CrlPath();
        var genCrlResult = await _runner.RunAsync(
            new[]
            {
                "ca", "-config", _environment.Paths.OpenSslConfig,
                "-gencrl", "-out", crlPath
            },
            _environment.PkiRootDirectory,
            $"CRL updated after revocation of '{userName}'.",
            cancellationToken);

        if (!genCrlResult.Success)
        {
            return genCrlResult;
        }

        return PkiOperationResult.Ok($"Certificate revoked for '{userName}'.", crlPath);
    }

    public async Task<PkiOperationResult> SignFileAsync(string userName, string filePath, CancellationToken cancellationToken = default)
    {
        var keyPath = _environment.Paths.UserPrivateKey(userName);
        if (!File.Exists(keyPath))
        {
            return PkiOperationResult.Fail($"Private key not found for '{userName}'.");
        }

        if (!File.Exists(filePath))
        {
            return PkiOperationResult.Fail($"File '{filePath}' was not found.");
        }

        var signaturePath = _environment.Paths.Signature(filePath);
        var result = await _runner.RunAsync(
            new[] { "dgst", "-sha256", "-sign", keyPath, "-out", signaturePath, filePath },
            Path.GetDirectoryName(Path.GetFullPath(filePath)) ?? _environment.PkiRootDirectory,
            $"Signature created at '{signaturePath}'.",
            cancellationToken);

        return result.Success ? PkiOperationResult.Ok($"Signature created for '{filePath}'.", signaturePath) : result;
    }

    public async Task<PkiOperationResult> VerifySignatureAsync(string userName, string filePath, CancellationToken cancellationToken = default)
    {
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

        var certificateCheck = await VerifyCertificateAsync(certPath, cancellationToken);
        if (!certificateCheck.Success)
        {
            return certificateCheck;
        }

        var publicKeyPath = Path.Combine(_environment.PkiRootDirectory, $"{userName}.pub.pem");
        try
        {
            var publicKeyPem = await _runner.RunCaptureAsync(new[] { "x509", "-pubkey", "-noout", "-in", certPath }, _environment.PkiRootDirectory, cancellationToken);
            await File.WriteAllTextAsync(publicKeyPath, publicKeyPem, cancellationToken);

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
            if (File.Exists(publicKeyPath))
            {
                File.Delete(publicKeyPath);
            }
        }
    }

    private async Task<PkiOperationResult> VerifyCertificateAsync(string certPath, CancellationToken cancellationToken)
    {
        var verifyArgs = new List<string>
        {
            "verify", "-CAfile", _environment.Paths.CaCertificate
        };

        var crlPath = _environment.Paths.CrlPath();
        if (File.Exists(crlPath))
        {
            verifyArgs.AddRange(new[] { "-crl_check", "-CRLfile", crlPath });
        }

        verifyArgs.Add(certPath);

        var result = await _runner.RunAsync(
            verifyArgs,
            _environment.PkiRootDirectory,
            $"Certificate verified for '{Path.GetFileNameWithoutExtension(certPath)}'.",
            cancellationToken);

        return result.Success ? PkiOperationResult.Ok($"Certificate verified for '{Path.GetFileNameWithoutExtension(certPath)}'.") : result;
    }

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

    private async Task WriteOpenSslConfigAsync(CancellationToken cancellationToken)
    {
        var config = BuildOpenSslConfig();
        await File.WriteAllTextAsync(_environment.Paths.OpenSslConfig, config, cancellationToken);
        if (!File.Exists(_environment.Paths.Database))
        {
            await File.WriteAllTextAsync(_environment.Paths.Database, string.Empty, cancellationToken);
        }

        if (!File.Exists(_environment.Paths.Serial))
        {
            await File.WriteAllTextAsync(_environment.Paths.Serial, "1000", cancellationToken);
        }

        if (!File.Exists(_environment.Paths.CrlNumber))
        {
            await File.WriteAllTextAsync(_environment.Paths.CrlNumber, "1000", cancellationToken);
        }
    }

    private string BuildOpenSslConfig()
    {
        var dir = NormalizePath(_environment.PkiRootDirectory);
        return $"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = {dir}
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

    private void ValidateReadyForIssue()
    {
        if (!File.Exists(_environment.Paths.CaKey) || !File.Exists(_environment.Paths.CaCertificate))
        {
            throw new InvalidOperationException("The CA is not initialized. Run CA initialization first.");
        }
    }

    private static string NormalizePath(string path) => Path.GetFullPath(path).Replace('\\', '/');
}

internal static class PkiPathsExtensions
{
    public static string CrlPath(this PkiPaths paths) => Path.Combine(paths.Crl, "ca.crl.pem");
}
