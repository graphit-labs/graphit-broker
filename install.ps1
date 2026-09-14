param(
    [string]$Dir = (Join-Path $env:LOCALAPPDATA 'Graphit\bin'),
    [string]$Version = $env:VERSION
)

$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw 'Only Windows amd64 releases are available.'
}
if (-not $Dir) { throw 'Installation directory cannot be empty.' }
if (-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) { throw 'tar.exe is required.' }

$repo = 'graphit-labs/graphit-broker'
if (-not $Version) {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
    $Version = $release.tag_name
}
if ($Version -cnotmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw "Invalid release tag: $Version" }
$archive = 'graphit-broker-windows-amd64.tar.gz'
$checksum = 'graphit-broker-windows-amd64.sha256'
$base = "https://github.com/$repo/releases/download/$Version"
$temp = Join-Path ([IO.Path]::GetTempPath()) ('graphit-broker-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
$stage = $null
try {
    $archivePath = Join-Path $temp $archive
    $checksumPath = Join-Path $temp $checksum
    Invoke-WebRequest -Uri "$base/$archive" -OutFile $archivePath
    Invoke-WebRequest -Uri "$base/$checksum" -OutFile $checksumPath
    $line = @(Get-Content $checksumPath | Where-Object { $_ -match ('(?i)^([a-f0-9]{64})\s+\*?' + [regex]::Escape($archive) + '$') })
    if ($line.Count -ne 1) { throw "Expected exactly one SHA-256 entry for $archive" }
    $expected = ([regex]::Match($line[0], '^[a-fA-F0-9]{64}')).Value
    $actual = (Get-FileHash -Algorithm SHA256 $archivePath).Hash
    if ($actual -ine $expected) { throw 'Archive SHA-256 mismatch.' }

    $entry = 'graphit-broker-windows-amd64/graphit-broker.exe'
    $entries = @(& tar.exe -tzf $archivePath)
    if ($LASTEXITCODE -ne 0 -or $entries -cnotcontains $entry) { throw 'Executable missing from archive.' }
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    $stage = Join-Path $Dir ('.graphit-broker-install-' + [guid]::NewGuid().ToString('N') + '.exe')
    $extracted = Join-Path $temp 'graphit-broker-windows-amd64'
    & tar.exe -xzf $archivePath -C $temp $entry
    if ($LASTEXITCODE -ne 0) { throw 'Could not extract executable.' }
    $extractedBin = Join-Path $extracted 'graphit-broker.exe'
    $item = Get-Item -LiteralPath $extractedBin
    if ($item -isnot [IO.FileInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -eq 0) {
        throw 'Release executable must be a nonempty regular file.'
    }
    Move-Item -LiteralPath $extractedBin -Destination $stage
    $destination = Join-Path $Dir 'graphit-broker.exe'
    $backup = $null
    if (Test-Path -LiteralPath $destination) {
        $backup = $destination + '.bak-' + [guid]::NewGuid().ToString('N')
        Move-Item -LiteralPath $destination -Destination $backup
    }
    try {
        Move-Item -LiteralPath $stage -Destination $destination
    } catch {
        if ($backup) { Move-Item -LiteralPath $backup -Destination $destination }
        throw
    }
    if ($backup) { Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue }
    Write-Host "Installed graphit-broker $Version at $destination"
    if (($env:PATH -split ';') -notcontains $Dir) { Write-Host "Add $Dir to PATH to run graphit-broker." }
    Write-Host 'Create your config separately; see docs/binary.md.'
} finally {
    if ($stage -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Force }
    Remove-Item -LiteralPath $temp -Recurse -Force
}
