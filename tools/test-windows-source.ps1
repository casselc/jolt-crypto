#requires -version 5
<#
.SYNOPSIS
  Run a checked-in jolt-crypto alias through native Windows Chez.

.DESCRIPTION
  Invokes Jolt's source-mode CLI directly from PowerShell. Native paths and
  Clojure source never pass through bash. The child handle and exit code are
  observed explicitly so PowerShell 5.1 cannot turn a failed test into success.
#>
param(
  [string]$ProjectPath = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [string]$RuntimePath = "D:\src\jolt-core-w9",
  [string]$ChezExe = "D:\chez-10.4.1\bin\scheme.exe",
  [string]$TestAlias = "-M:test",
  [string]$GitLibsPath = "",
  [string]$ScratchHome = "",
  [string]$ShellExe = "",
  [ValidateSet("x86-64", "aarch64")]
  [string]$ExpectedArch = "x86-64",
  [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ChezExe)) {
  throw "test-windows-source.ps1: scheme.exe not found at $ChezExe"
}
if (-not (Test-Path (Join-Path $RuntimePath "host\chez\cli.ss"))) {
  throw "test-windows-source.ps1: host\chez\cli.ss not found under $RuntimePath"
}
if ($TimeoutSeconds -le 0) {
  throw "test-windows-source.ps1: TimeoutSeconds must be positive"
}
if (-not $TestAlias.StartsWith("-M:")) {
  throw "test-windows-source.ps1: TestAlias must be a -M: alias"
}

if ([string]::IsNullOrWhiteSpace($ShellExe)) {
  $candidates = @(
    "$env:ProgramFiles\Git\bin\sh.exe",
    "${env:ProgramFiles(x86)}\Git\bin\sh.exe",
    "C:\Program Files\Git\bin\sh.exe"
  ) | Where-Object { $_ -and (Test-Path $_) }
  if ($candidates) {
    $ShellExe = $candidates[0]
  }
  else {
    $command = Get-Command sh -ErrorAction SilentlyContinue
    if ($command) {
      $ShellExe = $command.Source
    }
  }
}
if ([string]::IsNullOrWhiteSpace($ShellExe) -or -not (Test-Path $ShellExe)) {
  throw "test-windows-source.ps1: sh.exe not found; pass -ShellExe explicitly"
}

if ([string]::IsNullOrWhiteSpace($GitLibsPath)) {
  $GitLibsPath = Join-Path $ProjectPath ".jolt-cache\gitlibs"
}
if (-not (Test-Path $GitLibsPath)) {
  $null = New-Item -ItemType Directory -Force -Path $GitLibsPath
}
if ([string]::IsNullOrWhiteSpace($ScratchHome)) {
  $ScratchHome = Join-Path $ProjectPath ".jolt-cache\home"
}
if (-not (Test-Path $ScratchHome)) {
  $null = New-Item -ItemType Directory -Force -Path $ScratchHome
}

$env:JOLT_PWD = $ProjectPath
$env:JOLT_AOT_CACHE = "0"
$env:JOLT_VERSION = "dev"
$env:JOLT_SH = (Resolve-Path $ShellExe).Path
$env:JOLT_GITLIBS = (Resolve-Path $GitLibsPath).Path
$env:HOME = (Resolve-Path $ScratchHome).Path
$env:USERPROFILE = $env:HOME
$env:JOLT_EXPECT_OS = "windows"
$env:JOLT_EXPECT_ARCH = $ExpectedArch

$chezVersion = (& $ChezExe --version 2>&1 | Out-String).Trim()
if ($chezVersion -ne "10.4.1") {
  throw "test-windows-source.ps1: expected Chez 10.4.1, got '$chezVersion'"
}

Write-Host "jolt-crypto native Windows source gate"
Write-Host "  project  = $env:JOLT_PWD"
Write-Host "  runtime  = $RuntimePath"
Write-Host "  scheme   = $ChezExe ($chezVersion)"
Write-Host "  alias    = $TestAlias"
Write-Host "  expected = $env:JOLT_EXPECT_OS/$env:JOLT_EXPECT_ARCH"
Write-Host "  gitlibs  = $env:JOLT_GITLIBS"
Write-Host ""

$arguments = @("--script", "host\chez\cli.ss", $TestAlias)

Push-Location $RuntimePath
try {
  $process = Start-Process `
    -FilePath $ChezExe `
    -ArgumentList $arguments `
    -NoNewWindow `
    -PassThru

  # PowerShell 5.1 may leave ExitCode empty until the process handle has been
  # materialized. Refuse to turn an unobserved exit code into false success.
  $null = $process.Handle
  if ($process.WaitForExit($TimeoutSeconds * 1000)) {
    $exitCode = $process.ExitCode
    if ($null -eq $exitCode) {
      throw "test-windows-source.ps1: observed no process exit code"
    }
    if ($exitCode -ne 0) {
      throw "$TestAlias failed with exit code $exitCode"
    }
    Write-Host "$TestAlias exited $exitCode"
  }
  else {
    [Console]::Error.WriteLine(
      "$TestAlias timed out after $TimeoutSeconds seconds; terminating PID $($process.Id)"
    )
    try {
      $process.Kill()
      $process.WaitForExit()
    }
    catch {
      [Console]::Error.WriteLine(
        "failed to terminate timed-out PID $($process.Id): $($_.Exception.Message)"
      )
    }
    throw "$TestAlias timed out"
  }
}
finally {
  Pop-Location
}

Write-Host ""
Write-Host "resolved dependency origins:"
Get-ChildItem (Join-Path $env:JOLT_GITLIBS "git-v3") -Filter *.jolt-origin |
  ForEach-Object { Write-Host "  $(Get-Content $_.FullName -Raw)" }
