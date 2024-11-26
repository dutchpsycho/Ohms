if (Get-Command rustc -ErrorAction SilentlyContinue) {
    Write-Host "rust is already installed"
    rustc --version
    pause
    exit
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "this script requires admin"
    pause
    exit
}

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
    "x86_64-pc-windows-msvc"
} else {
    "i686-pc-windows-msvc"
}
Write-Host "system architecture -> $arch"

$installerUrl = "https://win.rustup.rs/$arch/rustup-init.exe"
$installerPath = "$env:TEMP\rustup-init.exe"
Write-Host "downloading rust installer for $arch..."
Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing

if (Test-Path $installerPath) {
    Write-Host "installing rust..."
    Start-Process -FilePath $installerPath -ArgumentList "-y" -Wait
    Remove-Item $installerPath -Force
} else {
    Write-Host "install failed"
    pause
    exit
}

$env:CARGO_HOME = "$env:USERPROFILE\.cargo"
[System.Environment]::SetEnvironmentVariable("CARGO_HOME", $env:CARGO_HOME, [System.EnvironmentVariableTarget]::Machine)

$path = "$env:CARGO_HOME\bin;$env:Path"
[System.Environment]::SetEnvironmentVariable("PATH", $path, [System.EnvironmentVariableTarget]::Machine)

if (Get-Command rustc -ErrorAction SilentlyContinue) {
    Write-Host "rust installed successfully :3"
    rustc --version
} else {
    Write-Host "rust install failed or path failed"
}

pause