# SPDX-License-Identifier: Apache-2.0
#Requires -Version 5.1
param(
    [string]$Toolchain,
    [string]$DependencyRoot = "$PSScriptRoot/.deps",
    [string]$Output = "$PSScriptRoot/build",
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. "$PSScriptRoot/scripts/fetch-dependencies.ps1"

function Get-AbsoluteBuildPath([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path)) { $Path = Join-Path (Get-Location).Path $Path }
    return [IO.Path]::GetFullPath($Path)
}
function Invoke-BuildTool([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw ('Build command failed: ' + [IO.Path]::GetFileName($Program)) }
}
if ($env:OS -ne 'Windows_NT') { throw 'This build targets Windows x64.' }
$DependencyRoot = Get-AbsoluteBuildPath $DependencyRoot
$Output = Get-AbsoluteBuildPath $Output
[void][IO.Directory]::CreateDirectory($DependencyRoot)
[void][IO.Directory]::CreateDirectory($Output)
$lock = Get-Content -LiteralPath "$PSScriptRoot/dependencies.lock.json" -Raw | ConvertFrom-Json
if ($lock.schema -ne 1) { throw 'Unsupported dependency lock schema.' }
$capstone = Get-LockedDependency 'capstone' $lock $DependencyRoot -Offline:$Offline
[void](Get-LockedDependency 'json' $lock $DependencyRoot -Offline:$Offline)
if ([string]::IsNullOrWhiteSpace($Toolchain)) {
    $Toolchain = Get-LockedDependency 'toolchain' $lock $DependencyRoot -Offline:$Offline
} else { $Toolchain = Get-AbsoluteBuildPath $Toolchain }
$source = Join-Path $PSScriptRoot 'src'
$cc = Join-Path $Toolchain 'bin/x86_64-w64-mingw32-clang.exe'
$cpp = Join-Path $Toolchain 'bin/x86_64-w64-mingw32-clang++.exe'
$ar = Join-Path $Toolchain 'bin/llvm-ar.exe'
$windres = Join-Path $Toolchain 'bin/x86_64-w64-mingw32-windres.exe'
foreach ($program in @($cc, $cpp, $ar, $windres)) {
    if (-not (Test-Path -LiteralPath $program -PathType Leaf)) { throw 'Required LLVM-MinGW build tool is missing.' }
}
$cFlags = @('-O2', '-DNDEBUG', '-DCAPSTONE_STATIC', '-DCAPSTONE_HAS_X86',
            '-DCAPSTONE_USE_SYS_DYN_MEM', '-DCAPSTONE_X86_ATT_DISABLE', "-I$capstone/include")
$cSources = @('cs.c', 'Mapping.c', 'MCInst.c', 'MCInstrDesc.c', 'MCRegisterInfo.c', 'SStream.c', 'utils.c',
    'arch/X86/X86Disassembler.c', 'arch/X86/X86DisassemblerDecoder.c', 'arch/X86/X86IntelInstPrinter.c',
    'arch/X86/X86InstPrinterCommon.c', 'arch/X86/X86Mapping.c', 'arch/X86/X86Module.c')
$cObjects = @()
foreach ($file in $cSources) {
    $object = Join-Path $Output (($file -replace '[/\\]', '_') + '.o')
    Invoke-BuildTool $cc ($cFlags + @('-c', (Join-Path $capstone $file), '-o', $object))
    $cObjects += $object
}
$library = Join-Path $Output 'libcapstone.a'
Invoke-BuildTool $ar (@('rcs', $library) + $cObjects)
$cppFlags = @('-std=c++20', '-O2', '-DNDEBUG', '-DUNICODE', '-D_UNICODE', '-DCAPSTONE_STATIC',
              '-Wall', '-Wextra', '-Wpedantic', "-I$capstone/include", "-I$DependencyRoot")
$objects = @()
foreach ($file in @('m01.cpp', 'm02.cpp', 'm03.cpp', 'm04.cpp', 'm05.cpp')) {
    $object = Join-Path $Output ($file + '.o')
    Invoke-BuildTool $cpp ($cppFlags + @('-c', (Join-Path $source $file), '-o', $object))
    $objects += $object
}
$resource = Join-Path $Output 'app-res.o'
Invoke-BuildTool $windres @('--input', (Join-Path $source 'app.rc'), '--include-dir', $source, '--output', $resource)
$link = $cppFlags + @('-static', '-s', '-municode', '-mwindows', (Join-Path $source 'launch.cpp')) +
        $objects + @($library, $resource, '-lbcrypt', '-lcomdlg32', '-luser32', '-lgdi32', '-lshell32',
                    '-o', (Join-Path $Output 'Native-Utility.exe'))
Invoke-BuildTool $cpp $link
Copy-Item -LiteralPath "$PSScriptRoot/licenses" -Destination $Output -Recurse -Force
foreach ($notice in @('LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md')) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $notice) -Destination $Output -Force
}
Write-Host ('Build complete: ' + (Join-Path $Output 'Native-Utility.exe'))
