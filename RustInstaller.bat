@echo off

where rustc >nul 2>&1
if %errorlevel% equ 0 (
    echo rust is already installed.
    rustc --version
    echo no further action required.
    pause
    exit /b
)

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo this script requires administrator privileges
    pause
    exit /b
)

set "ARCH="
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set "ARCH=x86_64-pc-windows-msvc"
) else (
    set "ARCH=i686-pc-windows-msvc"
)

echo detected system architecture: %ARCH%
echo downloading rust installer for %ARCH%...
powershell -Command "Invoke-WebRequest -Uri https://win.rustup.rs/%ARCH%/rustup-init.exe -OutFile rustup-init.exe"

if exist rustup-init.exe (
    echo installing rust...
    rustup-init.exe -y
    del rustup-init.exe
) else (
    echo failed to download rust installer for %ARCH%.
    pause
    exit /b
)

set "CARGO_HOME=%USERPROFILE%\.cargo"
setx CARGO_HOME "%CARGO_HOME%" /m

set PATH=%CARGO_HOME%\bin;%PATH%
setx PATH "%PATH%" /m

where rustc >nul 2>&1
if %errorlevel% equ 0 (
    echo rust installed successfully.
    rustc --version
) else (
    echo rust installation failed or is not in the path.
)

pause
