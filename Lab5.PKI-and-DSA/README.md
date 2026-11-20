# Lab 5: PKI and digital signatures

A C# console application that uses OpenSSL to create an internal Certificate Authority (CA), issue and revoke user certificates, and sign and verify files with RSA and SHA-256.

## Prerequisites

- .NET 10 SDK.
- OpenSSL available as `openssl` on your `PATH`.
- PowerShell for the examples below.

Run these commands from the repository root:

```powershell
Set-Location .\Lab5.PKI-and-DSA
dotnet --version
openssl version
dotnet build
dotnet run --no-build -- help
```

The `--` separates .NET CLI options from arguments passed to this application. The program accepts one command per run; it does not prompt for commands interactively.

## 1. Initialize the CA

```powershell
dotnet run --no-build -- init-ca --cn "Lab5 Root CA" --c MD --o "University" --ou "Cryptography Lab"
```

Expected result: `Internal CA is ready` followed by the PKI directory and CA certificate path. This creates a 4096-bit RSA key, a self-signed certificate valid for 3650 days, and an initial Certificate Revocation List (CRL).

Files are stored in `lab5-pki` inside the project directory. Running `init-ca` again preserves existing CA keys and certificates and regenerates the configuration and CRL. New subject options do not change an existing CA certificate.

## 2. Issue user certificates

For a fresh PKI, run:

```powershell
dotnet run --no-build -- issue-user alice --cn "Alice Example" --c MD --o "University" --email "alice@example.com"
dotnet run --no-build -- issue-user bob --cn "Bob Example" --c MD --o "University" --email "bob@example.com"
```

Expected result: `User certificate issued for 'alice'.` and the equivalent message for Bob. Each user receives a 2048-bit RSA key and a certificate valid for 365 days.

Subject options are optional; `issue-user alice` uses `alice` as the common name. Both `--cn "Alice Example"` and `--cn="Alice Example"` are supported.

User names must contain 1-64 ASCII letters, digits, hyphens, or underscores and start with a letter or digit. CA names (`ca`, `ca-chain`) and Windows device names are reserved.

Issuing another certificate for a user with an existing, unrevoked certificate fails. If you have already used these names, use different names throughout the examples or follow the revocation and reissuance steps below.

## 3. Create, sign, and verify a file

```powershell
New-Item -ItemType Directory -Path .\docs -Force | Out-Null
Set-Content -Path .\docs\message.txt -Value "Hello from the PKI laboratory."
dotnet run --no-build -- sign alice .\docs\message.txt
dotnet run --no-build -- verify alice .\docs\message.txt
```

Expected result: signing creates `docs/message.txt.sig`, and verification prints `Signature verified successfully`. Keep the `.sig` file alongside the original file. Both relative and absolute file paths work; quote paths containing spaces.

## 4. Test an incorrect signer

```powershell
dotnet run --no-build -- verify bob .\docs\message.txt
$LASTEXITCODE
```

Expected result: verification fails because Bob's public key does not match Alice's signature. The exit code is `1`. OpenSSL error details vary by version.

## 5. Test file tampering

```powershell
Set-Content -Path .\docs\message.txt -Value "This file has been changed."
dotnet run --no-build -- verify alice .\docs\message.txt
$LASTEXITCODE
```

Expected result: verification fails with exit code `1` because the file contents no longer match the signature.

Restore the original contents before testing revocation:

```powershell
Set-Content -Path .\docs\message.txt -Value "Hello from the PKI laboratory."
dotnet run --no-build -- verify alice .\docs\message.txt
```

Expected result: verification succeeds again with the original signature.

## 6. Revoke a certificate

```powershell
dotnet run --no-build -- revoke-user alice
dotnet run --no-build -- verify alice .\docs\message.txt
dotnet run --no-build -- sign alice .\docs\message.txt
```

Expected result: revocation succeeds and updates the CRL. Both verification and signing then fail with `certificate revoked`. Repeating `revoke-user alice` safely regenerates the CRL.

## 7. Issue a replacement certificate

```powershell
dotnet run --no-build -- issue-user alice --cn "Alice Example" --c MD --o "University" --email "alice@example.com"
dotnet run --no-build -- verify alice .\docs\message.txt
dotnet run --no-build -- sign alice .\docs\message.txt
dotnet run --no-build -- verify alice .\docs\message.txt
```

Expected result: issuance archives the revoked certificate under `lab5-pki/revoked` and creates a new key and certificate. Verification of the old signature fails with the new certificate. Signing again replaces the `.sig` file, after which verification succeeds.

## 8. Test invalid input

```powershell
dotnet run --no-build -- issue-user "../private/ca"
dotnet run --no-build -- issue-user ca
dotnet run --no-build -- sign bob .\docs\missing.txt
dotnet run --no-build -- unknown-command
```

Expected result: each command fails with a descriptive error and exit code `1`. Successful commands return `0`; check `$LASTEXITCODE` immediately after the command you want to inspect.

## Inspect the generated certificates

```powershell
openssl x509 -in .\lab5-pki\certs\ca.cert.pem -noout -subject -issuer -dates
openssl x509 -in .\lab5-pki\certs\alice.cert.pem -noout -subject -issuer -dates
openssl verify -CAfile .\lab5-pki\certs\ca.cert.pem -crl_check -CRLfile .\lab5-pki\crl\ca.crl.pem .\lab5-pki\certs\alice.cert.pem
openssl crl -in .\lab5-pki\crl\ca.crl.pem -noout -text
```

After the replacement certificate is issued, the verification command should report `OK`. The CRL still lists the earlier revoked certificate's serial number.

If the CRL is missing or expired, signing and verification fail. Run `dotnet run --no-build -- init-ca` to regenerate it from the CA database. The generated CRL is valid for 30 days.

## Run the automated regression checks

After the initial `dotnet build`, run this from the project directory using PowerShell 7:

```powershell
.\Verify-Lab.ps1
```

The script builds the project and runs 29 CLI checks, including relative paths, tampering, incorrect signers, revocation, missing CRLs, replacement certificates, and unsafe user names. It uses an isolated temporary PKI, leaving the project's `lab5-pki` unchanged. On success, it prints `Passed 29 CLI checks` and the location of the temporary artifacts.
