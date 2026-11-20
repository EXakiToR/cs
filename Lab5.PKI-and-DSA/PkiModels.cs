namespace Lab5.PKI_and_DSA;

/// <summary>
/// Encapsulates PKI policy settings for CA and user certificates.
/// Defines key sizes and validity periods for the internal CA infrastructure.
/// </summary>
internal sealed record PkiPolicy(int CaKeySize, int CaValidityDays, int UserKeySize, int UserValidityDays)
{
    /// <summary>
    /// Default PKI policy: 4096-bit RSA CA keys valid for 3650 days (10 years),
    /// and 2048-bit RSA user keys valid for 365 days (1 year).
    /// </summary>
    public static PkiPolicy Default { get; } = new(4096, 3650, 2048, 365);
}

/// <summary>
/// Represents the PKI environment configuration including workspace and PKI root directories,
/// as well as the OpenSSL executable path.
/// </summary>
internal sealed record PkiEnvironment(string WorkspaceRoot, string PkiRootDirectory, string OpenSslExecutable)
{
    /// <summary>
    /// Factory method to create a PkiEnvironment from a workspace root directory.
    /// </summary>
    /// <param name="workspaceRoot">The root directory of the workspace.</param>
    /// <param name="openSslExecutable">Optional custom path to the OpenSSL executable. Defaults to "openssl".</param>
    /// <param name="pkiRootDirectory">Optional custom subdirectory name for PKI storage. Defaults to "lab5-pki".</param>
    /// <returns>A configured PkiEnvironment instance.</returns>
    public static PkiEnvironment Create(string workspaceRoot, string? openSslExecutable = null, string? pkiRootDirectory = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workspaceRoot);

        return new PkiEnvironment(
            Path.GetFullPath(workspaceRoot),
            Path.GetFullPath(Path.Combine(workspaceRoot, pkiRootDirectory ?? "lab5-pki")),
            string.IsNullOrWhiteSpace(openSslExecutable) ? "openssl" : openSslExecutable);
    }

    /// <summary>
    /// Gets the path structure object for accessing all PKI files and directories.
    /// </summary>
    public PkiPaths Paths => new(PkiRootDirectory);
}

/// <summary>
/// Provides consistent path management for all PKI artifacts including keys, certificates,
/// certificate signing requests, revoked certificates, and certificate revocation lists.
/// </summary>
internal sealed record PkiPaths(string Root)
{
    // Directory paths
    public string Private => Path.Combine(Root, "private");
    public string Certificates => Path.Combine(Root, "certs");
    public string NewCertificates => Path.Combine(Root, "newcerts");
    public string Requests => Path.Combine(Root, "requests");
    public string Revoked => Path.Combine(Root, "revoked");
    public string Crl => Path.Combine(Root, "crl");

    // CA database and configuration files
    public string Database => Path.Combine(Root, "index.txt");
    public string Serial => Path.Combine(Root, "serial");
    public string CrlNumber => Path.Combine(Root, "crlnumber");

    // CA certificate and key paths
    public string CaKey => Path.Combine(Private, "ca.key.pem");
    public string CaCertificate => Path.Combine(Certificates, "ca.cert.pem");
    public string CaChain => Path.Combine(Certificates, "ca-chain.cert.pem");
    public string OpenSslConfig => Path.Combine(Root, "openssl.cnf");

    /// <summary>Gets the path to a user's private key file.</summary>
    public string UserPrivateKey(string userName) => Path.Combine(Private, $"{ValidateUserName(userName)}.key.pem");

    /// <summary>Gets the path to a user's certificate signing request (CSR) file.</summary>
    public string UserRequest(string userName) => Path.Combine(Requests, $"{ValidateUserName(userName)}.csr.pem");

    /// <summary>Gets the path to a user's issued certificate file.</summary>
    public string UserCertificate(string userName) => Path.Combine(Certificates, $"{ValidateUserName(userName)}.cert.pem");

    /// <summary>Gets the path to a user's revoked certificate file.</summary>
    public string UserRevokedCertificate(string userName) => Path.Combine(Revoked, $"{ValidateUserName(userName)}.cert.pem");

    private static string ValidateUserName(string userName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        if (userName.Length > 64 || !char.IsAsciiLetterOrDigit(userName[0]) ||
            userName.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_') ||
            userName.Equals("ca", StringComparison.OrdinalIgnoreCase) ||
            userName.Equals("ca-chain", StringComparison.OrdinalIgnoreCase) ||
            new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" }.Contains(userName, StringComparer.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Use a user name of 1-64 ASCII letters, digits, hyphens or underscores, starting with a letter or digit. CA and device names are reserved.");
        }

        return userName;
    }

    /// <summary>Gets the path to a file's digital signature file (appends .sig extension).</summary>
    public string Signature(string filePath) => filePath + ".sig";
}

/// <summary>
/// Represents the result of a PKI operation, indicating success or failure along with messages
/// and optional artifact paths (e.g., generated certificate paths).
/// </summary>
internal sealed record PkiOperationResult(bool Success, string Message, string? ArtifactPath = null)
{
    /// <summary>Creates a successful operation result.</summary>
    public static PkiOperationResult Ok(string message, string? artifactPath = null) => new(true, message, artifactPath);

    /// <summary>Creates a failed operation result.</summary>
    public static PkiOperationResult Fail(string message) => new(false, message);
}

/// <summary>
/// Represents an X.509 certificate subject name with components like Common Name (CN),
/// Country (C), Organization (O), Organizational Unit (OU), and Email.
/// </summary>
internal sealed record SubjectName(string CommonName, string? Country = null, string? Organization = null, string? OrganizationalUnit = null, string? Email = null)
{
    /// <summary>
    /// Converts this subject name to an OpenSSL distinguished name (DN) string format.
    /// Example: "/C=US/O=MyOrg/CN=example.com"
    /// </summary>
    /// <returns>An OpenSSL-compatible distinguished name string.</returns>
    public string ToOpenSslDistinguishedName()
    {
        var parts = new List<string>();

        // Local helper to add DN components, escaping forward slashes as needed
        void Add(string label, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                parts.Add($"/{label}={Escape(value)}");
            }
        }

        // Build DN in standard order: C, O, OU, CN, emailAddress
        Add("C", Country);
        Add("O", Organization);
        Add("OU", OrganizationalUnit);
        Add("CN", CommonName);
        Add("emailAddress", Email);
        return string.Concat(parts);
    }

    /// <summary>Escapes forward slashes in subject name values for OpenSSL DN format.</summary>
    private static string Escape(string value) => value.Replace("\\", "\\\\").Replace("/", "\\/").Replace("+", "\\+");
}
