param(
    [string]$Dir = (Join-Path $env:LOCALAPPDATA 'Programs\graphit-broker'),
    [string]$Version = $env:VERSION,
    [string]$Archive
)

$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw 'Only Windows amd64 releases are available.'
}
if (-not $Dir) { throw 'Installation directory cannot be empty.' }
if (-not (Get-Command tar.exe -ErrorAction SilentlyContinue)) { throw 'tar.exe is required.' }
$Dir = [IO.Path]::GetFullPath($Dir)
$repo = 'graphit-labs/graphit-broker'
$archiveName = 'graphit-broker-windows-amd64.tar.gz'
$checksumName = 'graphit-broker-windows-amd64.sha256'
if ($Archive) {
    if ($Version) { throw '-Archive and -Version cannot be combined.' }
    if (-not $Archive.EndsWith('.tar.gz', [StringComparison]::OrdinalIgnoreCase)) { throw '-Archive requires a .tar.gz archive.' }
    $Archive = (Get-Item -LiteralPath $Archive).FullName
    $localChecksum = $Archive.Substring(0, $Archive.Length - 7) + '.sha256'
    if (-not (Test-Path -LiteralPath $localChecksum -PathType Leaf)) { throw 'Adjacent .sha256 is missing.' }
} else {
    if (-not $Version) {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
        $Version = $release.tag_name
    }
    if ($Version -cnotmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw "Invalid release tag: $Version" }
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('graphit-broker-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $archivePath = Join-Path $temp $archiveName
    $checksumPath = Join-Path $temp $checksumName
    if ($Archive) {
        Copy-Item -LiteralPath $Archive -Destination $archivePath
        Copy-Item -LiteralPath $localChecksum -Destination $checksumPath
    } else {
        $base = "https://github.com/$repo/releases/download/$Version"
        Invoke-WebRequest -Uri "$base/$archiveName" -OutFile $archivePath
        Invoke-WebRequest -Uri "$base/$checksumName" -OutFile $checksumPath
    }
    $line = @(Get-Content $checksumPath | Where-Object { $_ -match ('(?i)^([a-f0-9]{64})\s+\*?' + [regex]::Escape($archiveName) + '$') })
    if ($line.Count -ne 1) { throw "Expected exactly one SHA-256 entry for $archiveName" }
    $expected = ([regex]::Match($line[0], '^[a-fA-F0-9]{64}')).Value
    if ((Get-FileHash -Algorithm SHA256 $archivePath).Hash -ine $expected) { throw 'Archive SHA-256 mismatch.' }

    $root = 'graphit-broker-windows-amd64'
    $required = @('graphit-broker.exe', 'graphit-runtime/broker/windows-libraries.json',
        'graphit-runtime/licenses/broker/LICENSE', 'graphit-runtime/licenses/broker/ggml/LICENSE',
        'graphit-runtime/licenses/broker/ggml/LICENSE-MIT', 'graphit-runtime/licenses/broker/ggml/LICENSE-APACHE', 'graphit-runtime/licenses/broker/nvidia/LICENSE', 'graphit-runtime/licenses/broker/ggml/licenses/LICENSE-jsonhpp')
    $entries = @(& tar.exe -tzf $archivePath)
    if ($LASTEXITCODE -ne 0) { throw 'Could not list release archive.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
        if (-not $seen.Add($entry) -or -not $entry.StartsWith($root + '/', [StringComparison]::Ordinal)) { throw 'Invalid or duplicate archive member.' }
        $relative = $entry.Substring($root.Length + 1)
        if ($required -ccontains $relative) { continue }
        if ($relative -cmatch '^[A-Za-z0-9][A-Za-z0-9_.+-]*\.dll$') { continue }
        if ($relative -cmatch '^graphit-runtime/broker/licenses/windows-amd64/[A-Za-z0-9][A-Za-z0-9_.+-]*\.txt$') { continue }
        throw 'Unexpected archive member.'
    }
    foreach ($name in $required) {
        if ($entries -cnotcontains "$root/$name") { throw "Required archive member missing: $name" }
    }
    $types = @(& tar.exe -tvzf $archivePath)
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect archive member types.' }
    foreach ($type in $types) { if (-not $type.StartsWith('-')) { throw 'Archive members must be regular files.' } }
    & tar.exe -xzf $archivePath -C $temp
    if ($LASTEXITCODE -ne 0) { throw 'Could not extract release payload.' }
    $payload = Join-Path $temp $root
    foreach ($entry in $entries) {
        $file = Get-Item -LiteralPath (Join-Path $payload $entry.Substring($root.Length + 1))
        if ($file -isnot [IO.FileInfo] -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -eq 0) {
            throw 'Release payload must contain nonempty regular files.'
        }
    }
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $payload 'graphit-runtime/broker/windows-libraries.json') | ConvertFrom-Json
    if ($manifest.platform -cne 'windows-amd64') { throw 'Wrong native runtime platform.' }
    if (@($manifest.executables).Count -ne 1 -or $manifest.executables[0].file -cne 'graphit-broker.exe') { throw 'Native executable manifest mismatch.' }
    $declared = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($library in @($manifest.libraries)) {
        if ($library.file -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.+-]*\.dll$' -or -not $declared.Add($library.file)) { throw 'Invalid native library manifest.' }
    }
    $dlls = @($entries | Where-Object { $_ -cmatch '\.dll$' })
    if ($dlls.Count -ne $declared.Count) { throw 'Native runtime library set mismatch.' }
    foreach ($dll in $dlls) { if (-not $declared.Contains($dll.Substring($root.Length + 1))) { throw 'Undeclared native runtime library.' } }
    foreach ($record in @($manifest.executables) + @($manifest.libraries)) {
        $member = "$root/$($record.file)"
        if ($entries -cnotcontains $member -or (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $payload $record.file)).Hash -ine $record.sha256) {
            throw 'Native runtime manifest integrity mismatch.'
        }
    }

    foreach ($library in @($manifest.libraries)) {
        $notice = $null
        if ($library.file -match '^(msvcp140|vcruntime140|concrt140)') { $notice = 'Microsoft-VC-REDIST-NOTICE.txt' }
        if ($library.file -match '^lib(ssl|crypto)-3-x64\.dll$') { $notice = 'OpenSSL-LICENSE.txt' }
        if ($notice -and $entries -cnotcontains "$root/graphit-runtime/broker/licenses/windows-amd64/$notice") { throw 'Native runtime license missing.' }
    }

    # DLLs stay app-local next to the executable. The default Broker directory is
    # distinct from Code, preserving each product's selected native runtime.
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    $ordered = @($entries | Where-Object { $_ -cne "$root/graphit-broker.exe" }) + @("$root/graphit-broker.exe")
    foreach ($entry in $ordered) {
        $relative = $entry.Substring($root.Length + 1)
        $destination = Join-Path $Dir $relative
        $parent = Split-Path -Parent $destination
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
        $stage = Join-Path $parent ('.broker-install-' + [guid]::NewGuid().ToString('N'))
        $backup = $null
        try {
            Copy-Item -LiteralPath (Join-Path $payload $relative) -Destination $stage
            if (Test-Path -LiteralPath $destination) {
                $backup = $destination + '.replacing-' + [guid]::NewGuid().ToString('N')
                Move-Item -LiteralPath $destination -Destination $backup
            }
            try { Move-Item -LiteralPath $stage -Destination $destination }
            catch {
                if ($backup) { Move-Item -LiteralPath $backup -Destination $destination }
                throw
            }
            if ($backup) { Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue }
        } finally {
            if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Force }
        }
    }
    $label = if ($Archive) { 'local archive' } else { $Version }
    Write-Host "Installed graphit-broker $label at $(Join-Path $Dir 'graphit-broker.exe')"
    if (($env:PATH -split ';') -notcontains $Dir) { Write-Host "Add $Dir to PATH to run graphit-broker." }
    Write-Host 'Create your config separately; see docs/binary.md.'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}
