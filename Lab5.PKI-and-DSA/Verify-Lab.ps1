param()

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$project = Join-Path $PSScriptRoot 'Lab5.PKI-and-DSA.csproj'
& dotnet build $project --no-restore --disable-build-servers
if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }

# The copied executable resolves its PKI root three levels above its binary.
# Include configuration metacharacters to exercise OpenSSL path escaping.
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('lab5 # $ regression-' + [guid]::NewGuid().ToString('N'))
$testBin = Join-Path $testRoot 'bin/Debug/net10.0'
New-Item -ItemType Directory -Path $testBin -Force | Out-Null
Copy-Item -Path (Join-Path $PSScriptRoot 'bin/Debug/net10.0/*') -Destination $testBin
$testDll = Join-Path $testBin 'Lab5.PKI-and-DSA.dll'
$script:checks = 0

function Assert-Command {
    param([int]$ExpectedExit, [string[]]$CliArguments)
    $output = & dotnet $testDll @CliArguments 2>&1
    if ($LASTEXITCODE -ne $ExpectedExit) {
        throw "Unexpected exit code for [$($CliArguments -join ' ')]: $output"
    }
    $script:checks++
}

Push-Location $testRoot
try {
    Assert-Command 0 @('init-ca')
    Assert-Command 0 @('issue-user', 'alice')
    Assert-Command 0 @('issue-user', 'bob')
    Assert-Command 1 @('issue-user', 'alice')
    $caHash = (Get-FileHash 'lab5-pki/private/ca.key.pem').Hash
    foreach ($name in @('../private/ca', '..\private\ca', 'CA', 'ca-chain', 'NUL')) {
        Assert-Command 1 @('issue-user', $name)
    }
    if ((Get-FileHash 'lab5-pki/private/ca.key.pem').Hash -ne $caHash) { throw 'CA key changed.' }

    New-Item -ItemType Directory -Path 'docs' | Out-Null
    Set-Content 'docs/message.txt' 'Original message'
    Assert-Command 0 @('sign', 'alice', 'docs/message.txt')
    Assert-Command 0 @('verify', 'alice', 'docs/message.txt')
    Assert-Command 1 @('verify', 'bob', 'docs/message.txt')
    Set-Content 'docs/message.txt' 'Tampered message'
    Assert-Command 1 @('verify', 'alice', 'docs/message.txt')
    Set-Content 'docs/message.txt' 'Original message'
    Assert-Command 0 @('revoke-user', 'alice')
    Assert-Command 0 @('revoke-user', 'alice')
    Assert-Command 1 @('verify', 'alice', 'docs/message.txt')
    Assert-Command 1 @('sign', 'alice', 'docs/message.txt')

    Move-Item 'lab5-pki/crl/ca.crl.pem' 'lab5-pki/crl/ca.crl.pem.bak'
    Assert-Command 1 @('verify', 'alice', 'docs/message.txt')
    Assert-Command 1 @('sign', 'bob', 'docs/message.txt')
    Assert-Command 0 @('init-ca')
    Assert-Command 1 @('verify', 'alice', 'docs/message.txt')

    Assert-Command 0 @('issue-user', 'alice')
    if (@(Get-ChildItem 'lab5-pki/revoked/*.cert.pem').Count -ne 1) { throw 'Revoked certificate was not archived.' }
    Assert-Command 1 @('verify', 'alice', 'docs/message.txt')
    Assert-Command 0 @('sign', 'alice', 'docs/message.txt')
    Assert-Command 0 @('verify', 'alice', 'docs/message.txt')
    Assert-Command 0 @('revoke-user', 'alice')
    Assert-Command 0 @('issue-user', 'alice')
    if (@(Get-ChildItem 'lab5-pki/revoked/*.cert.pem').Count -ne 2) { throw 'Earlier archive was overwritten.' }
    Assert-Command 0 @('sign', 'alice', 'docs/message.txt')
    Assert-Command 0 @('verify', 'alice', 'docs/message.txt')
    Write-Output "Passed $script:checks CLI checks. Isolated artifacts: $testRoot"
}
finally {
    Pop-Location
}
