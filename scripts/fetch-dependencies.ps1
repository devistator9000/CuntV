# SPDX-License-Identifier: Apache-2.0
#Requires -Version 5.1
Set-StrictMode -Version Latest

function Assert-CacheChild {
    param([string]$Root, [string]$Path)
    $parent = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $child = [IO.Path]::GetFullPath($Path)
    if (-not $child.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Dependency path escapes the cache directory.'
    }
    return $child
}

function Get-VerifiedDownload {
    param($Spec, [string]$Root, [switch]$Offline)
    if ($Spec.sha256 -notmatch '^[0-9a-f]{64}$' -or ([uri]$Spec.url).Scheme -ne 'https') {
        throw 'A dependency must have an HTTPS URL and a SHA-256 checksum.'
    }
    $cache = Join-Path $Root 'downloads'
    [void][IO.Directory]::CreateDirectory($cache)
    $file = Assert-CacheChild $Root (Join-Path $cache ($Spec.sha256 + '.download'))
    if (Test-Path -LiteralPath $file -PathType Leaf) {
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -eq $Spec.sha256) { return $file }
        if ($Offline) { throw 'Cached dependency checksum mismatch; offline build cannot continue.' }
        Remove-Item -LiteralPath $file -Force
    }
    if ($Offline) { throw 'A dependency is missing from the offline cache. Run an online build first.' }
    $partial = Assert-CacheChild $Root ($file + '.' + [guid]::NewGuid().ToString('N') + '.partial')
    try {
        Write-Host ('Downloading pinned dependency version ' + $Spec.version + '...')
        # Needed by older Windows PowerShell installations; does not disable certificate validation.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Uri $Spec.url -OutFile $partial
        if ((Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash -ne $Spec.sha256) {
            throw 'Dependency SHA-256 verification failed.'
        }
        Move-Item -LiteralPath $partial -Destination $file
    } finally {
        if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
    }
    return $file
}

function Expand-CheckedArchive {
    param([string]$Archive, [string]$Destination)
    [void][IO.Directory]::CreateDirectory($Destination)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        # Validate every member before extracting any file.
        foreach ($entry in $zip.Entries) {
            if ([IO.Path]::IsPathRooted($entry.FullName) -or $entry.FullName.Contains(':')) {
                throw 'Absolute paths and alternate data streams are not permitted in dependency archives.'
            }
            $target = Join-Path $Destination $entry.FullName
            [void](Assert-CacheChild $Destination $target)
        }
        foreach ($entry in $zip.Entries) {
            $target = Assert-CacheChild $Destination (Join-Path $Destination $entry.FullName)
            if ([string]::IsNullOrEmpty($entry.Name)) {
                [void][IO.Directory]::CreateDirectory($target)
            } else {
                [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $false)
            }
        }
    } finally { $zip.Dispose() }
}

function Get-LockedDependency {
    param([string]$Name, $Lock, [string]$Root, [switch]$Offline)
    $entry = $Lock.dependencies.PSObject.Properties[$Name]
    if ($null -eq $entry) { throw ('Unknown dependency: ' + $Name) }
    $spec = $entry.Value
    if ($spec.kind -eq 'file') {
        $target = Assert-CacheChild $Root (Join-Path $Root $spec.file)
        if ((Test-Path -LiteralPath $target -PathType Leaf) -and
            (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -eq $spec.sha256) { return $target }
        $download = Get-VerifiedDownload $spec $Root -Offline:$Offline
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
        Copy-Item -LiteralPath $download -Destination $target -Force
        return $target
    }
    if ($spec.kind -ne 'zip') { throw 'Unsupported dependency archive type.' }
    $final = Assert-CacheChild $Root (Join-Path $Root $spec.directory)
    $marker = Join-Path $final '.source.sha256'
    $ready = Test-Path -LiteralPath $marker -PathType Leaf
    if ($ready) { $ready = ([IO.File]::ReadAllText($marker).Trim() -eq $spec.sha256) }
    foreach ($required in $spec.required) {
        $path = Assert-CacheChild $final (Join-Path $final $required)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { $ready = $false }
    }
    if ($ready) { return $final }
    if (Test-Path -LiteralPath $final) {
        throw ('Incomplete dependency directory: ' + $final + '. Choose a fresh -DependencyRoot to rebuild it.')
    }
    $download = Get-VerifiedDownload $spec $Root -Offline:$Offline
    $stage = Assert-CacheChild $Root (Join-Path $Root ('.stage-' + [guid]::NewGuid().ToString('N')))
    try {
        Expand-CheckedArchive $download $stage
        $extracted = Assert-CacheChild $stage (Join-Path $stage $spec.directory)
        foreach ($required in $spec.required) {
            $path = Assert-CacheChild $extracted (Join-Path $extracted $required)
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Dependency archive is incomplete.' }
        }
        [IO.File]::WriteAllText((Join-Path $extracted '.source.sha256'), $spec.sha256)
        # Both source and destination have been checked inside this generated cache.
        [void](Assert-CacheChild $Root $extracted)
        [void](Assert-CacheChild $Root $final)
        Move-Item -LiteralPath $extracted -Destination $final
    } finally {
        if (Test-Path -LiteralPath $stage) {
            [void](Assert-CacheChild $Root $stage)
            Remove-Item -LiteralPath $stage -Recurse -Force
        }
    }
    return $final
}
