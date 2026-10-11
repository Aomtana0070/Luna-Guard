param(
    [Parameter(Mandatory = $true)]
    [string]$Artifact
)

$ErrorActionPreference = "Stop"
if (-not $env:WINDOWS_SIGNING_CERTIFICATE_BASE64 -or -not $env:WINDOWS_SIGNING_CERTIFICATE_PASSWORD) {
    throw "Windows signing secrets are required for a tagged release."
}

$pfxPath = Join-Path $env:RUNNER_TEMP "lunaguard-signing.pfx"
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new("My", "CurrentUser")
$certificate = $null
try {
    $pfxBytes = [Convert]::FromBase64String(($env:WINDOWS_SIGNING_CERTIFICATE_BASE64 -replace '\s', ''))
    [IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
    $securePassword = ConvertTo-SecureString $env:WINDOWS_SIGNING_CERTIFICATE_PASSWORD -AsPlainText -Force
    $certificate = @(Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $securePassword) |
        Where-Object { $_.HasPrivateKey } | Select-Object -First 1
    if (-not $certificate -or -not $certificate.HasPrivateKey) {
        throw "The PFX did not provide a usable private key."
    }
    $hasCodeSigningUsage = @($certificate.Extensions | Where-Object {
        $_.Oid.Value -eq "2.5.29.37" -and $_.EnhancedKeyUsages.Value -contains "1.3.6.1.5.5.7.3.3"
    }).Count -gt 0
    if (-not $hasCodeSigningUsage) { throw "The certificate does not include the Code Signing usage." }

    $signtoolCommand = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($signtoolCommand) {
        $signtool = $signtoolCommand.Source
    }
    else {
        $kits = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
        $signtool = Get-ChildItem -LiteralPath $kits -Filter signtool.exe -Recurse -ErrorAction Stop |
            Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
        if (-not $signtool) { throw "Windows SDK signtool.exe was not found." }
    }
    & $signtool sign /sha1 $certificate.Thumbprint /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /v $Artifact
    if ($LASTEXITCODE -ne 0) { throw "signtool failed to sign the Windows executable." }
    & $signtool verify /pa /all /v $Artifact
    if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed for the Windows executable." }
}
finally {
    try {
        if ($certificate) {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            try { $store.Remove($certificate) }
            finally { $store.Close() }
            $certificate.Dispose()
        }
    }
    finally {
        $store.Dispose()
        Remove-Item -LiteralPath $pfxPath -Force -ErrorAction SilentlyContinue
    }
}
