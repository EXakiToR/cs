namespace Lab5.PKI_and_DSA;

internal sealed record PkiPolicy(int CaKeySize, int CaValidityDays, int UserKeySize, int UserValidityDays)
{
    public static PkiPolicy Default { get; } = new(4096, 3650, 2048, 365);
}

internal sealed record PkiEnvironment(string WorkspaceRoot, string PkiRootDirectory, string OpenSslExecutable)
{
    public static PkiEnvironment Create(string workspaceRoot, string? openSslExecutable = null, string? pkiRootDirectory = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workspaceRoot);

        return new PkiEnvironment(
            Path.GetFullPath(workspaceRoot),
            Path.GetFullPath(Path.Combine(workspaceRoot, pkiRootDirectory ?? "lab5-pki")),
            string.IsNullOrWhiteSpace(openSslExecutable) ? "openssl" : openSslExecutable);
    }

    public PkiPaths Paths => new(PkiRootDirectory);
}

internal sealed record PkiPaths(string Root)
{
    public string Private => Path.Combine(Root, "private");
    public string Certificates => Path.Combine(Root, "certs");
    public string NewCertificates => Path.Combine(Root, "newcerts");
    public string Requests => Path.Combine(Root, "requests");
    public string Revoked => Path.Combine(Root, "revoked");
    public string Crl => Path.Combine(Root, "crl");
    public string Database => Path.Combine(Root, "index.txt");
    public string Serial => Path.Combine(Root, "serial");
    public string CrlNumber => Path.Combine(Root, "crlnumber");
    public string CaKey => Path.Combine(Private, "ca.key.pem");
    public string CaCertificate => Path.Combine(Certificates, "ca.cert.pem");
    public string CaChain => Path.Combine(Certificates, "ca-chain.cert.pem");
    public string OpenSslConfig => Path.Combine(Root, "openssl.cnf");

    public string UserPrivateKey(string userName) => Path.Combine(Private, $"{userName}.key.pem");
    public string UserRequest(string userName) => Path.Combine(Requests, $"{userName}.csr.pem");
    public string UserCertificate(string userName) => Path.Combine(Certificates, $"{userName}.cert.pem");
    public string UserRevokedCertificate(string userName) => Path.Combine(Revoked, $"{userName}.cert.pem");
    public string Signature(string filePath) => filePath + ".sig";
}

internal sealed record PkiOperationResult(bool Success, string Message, string? ArtifactPath = null)
{
    public static PkiOperationResult Ok(string message, string? artifactPath = null) => new(true, message, artifactPath);
    public static PkiOperationResult Fail(string message) => new(false, message);
}

internal sealed record SubjectName(string CommonName, string? Country = null, string? Organization = null, string? OrganizationalUnit = null, string? Email = null)
{
    public string ToOpenSslDistinguishedName()
    {
        var parts = new List<string>();

        void Add(string label, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                parts.Add($"/{label}={Escape(value)}");
            }
        }

        Add("C", Country);
        Add("O", Organization);
        Add("OU", OrganizationalUnit);
        Add("CN", CommonName);
        Add("emailAddress", Email);
        return string.Concat(parts);
    }

    private static string Escape(string value) => value.Replace("/", "\\/");
}
