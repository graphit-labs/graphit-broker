param([Parameter(Mandatory = $true)][string]$Archive)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$Archive = (Resolve-Path -LiteralPath $Archive).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ('broker-installer-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
# -Archive must never contact GitHub, even when no credentials/network exist.
function Invoke-WebRequest { throw 'Local installation attempted a download.' }
function Invoke-RestMethod { throw 'Local installation attempted discovery.' }
try {
    $destination = Join-Path $root 'install α'
    New-Item -ItemType Directory -Path (Join-Path $destination 'graphit-runtime') -Force | Out-Null
    $marker = Join-Path $destination 'graphit-runtime/build.json'
    Set-Content -LiteralPath $marker -Value 'unrelated Code build receipt' -NoNewline
    & (Join-Path $repo 'install.ps1') -Archive $Archive -Dir $destination
    if ((Get-Content -Raw -LiteralPath $marker) -cne 'unrelated Code build receipt') { throw 'Code receipt was changed.' }
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $destination 'graphit-runtime/broker/windows-libraries.json') | ConvertFrom-Json
    foreach ($item in @($manifest.executables) + @($manifest.libraries)) {
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $destination $item.file)).Hash -ine $item.sha256) { throw 'Installed runtime digest differs.' }
    }
    $relocated = Join-Path $root 'relocated β'
    Move-Item -LiteralPath $destination -Destination $relocated
    $originalPath = $env:PATH
    try {
        $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
        $version = & (Join-Path $relocated 'graphit-broker.exe') --version
        if ($LASTEXITCODE -ne 0 -or $version -notmatch '^graphit-broker [0-9]+\.[0-9]+\.[0-9]+$') { throw 'Relocated package did not start.' }
    } finally { $env:PATH = $originalPath }
    & (Join-Path $repo 'install.ps1') -Archive $Archive -Dir $relocated
    $before = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $relocated 'graphit-broker.exe')).Hash
    $damaged = Join-Path $root 'graphit-broker-windows-amd64.tar.gz'
    Copy-Item -LiteralPath $Archive -Destination $damaged
    Set-Content -LiteralPath ($damaged.Substring(0, $damaged.Length - 7) + '.sha256') -Value (('0' * 64) + '  graphit-broker-windows-amd64.tar.gz')
    $rejected = $false
    try { & (Join-Path $repo 'install.ps1') -Archive $damaged -Dir $relocated }
    catch { if ($_ -notmatch 'SHA-256 mismatch') { throw }; $rejected = $true }
    if (-not $rejected -or (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $relocated 'graphit-broker.exe')).Hash -cne $before) { throw 'Invalid package changed the installation.' }
    Write-Host 'PASS: complete app-local package, preservation, relocation, repeat and invalid checksum.'
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
