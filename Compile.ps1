$ErrorActionPreference = "Stop"

$projectRoot = (Get-Location).Path

$buildDir = Join-Path $projectRoot "build"
$targetDir = Join-Path $projectRoot "target"
$outputExe = Join-Path $targetDir "release\Ohms.exe"
$finalExe = Join-Path $buildDir "Ohms.exe"

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "cargo is not installed. run RustInstaller.ps1 to install it."
    exit 1
}

if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

Write-Host "compiling..."
Write-Host "if it slows down on capstone-sys, dw its a large package. not stuck."
Write-Host "the consoles will close when done, Ohms.exe will be in /build/"

Start-Process -FilePath "cargo" -ArgumentList "build --release" -Wait

if (-not (Test-Path $outputExe)) {
    Write-Host "build failed"
    exit 1
}

Move-Item -Path $outputExe -Destination $finalExe -Force

Write-Host "getting rid of artifacts..."
Remove-Item -Recurse -Force -Path $targetDir

Write-Host "done, Ohms.exe is in /build/"