# ==============================================================================
#  SHADOW CAT — Windows PowerShell One-Liner Installer
#  Usage: irm https://thanakorn30006.github.io/install.ps1 | iex
# ==============================================================================

$ErrorActionPreference = "Stop"

Write-Host @"
  ____  _   _    _    ____   _____        __   ____    _  _____ 
 / ___|| | | |  / \  |  _ \ / _ \ \      / /  / ___|  / \|_   _|
 \___ \| |_| | / _ \ | | | | | | \ \ /\ / /  | |     / _ \ | |  
  ___) |  _  |/ ___ \| |_| | |_| |\ V  V /   | |___ / ___ \| |  
 |____/|_| |_/_/   \_\____/ \___/  \_/\_/     \____/_/   \_\_|  
"@ -ForegroundColor Cyan

Write-Host "[+] Fetching SHADOW CAT for Windows (PowerShell)..." -ForegroundColor Green

# 1. Check Python
$pythonCmd = $null
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pythonCmd = "python3"
} else {
    Write-Host "[!] Python is not installed. Please install Python 3.9+ from python.org or Microsoft Store." -ForegroundColor Red
    exit 1
}

$pyVer = & $pythonCmd --version
Write-Host "    Found: $pyVer" -ForegroundColor Green

# 2. Directory Paths
$targetDir = Join-Path $HOME "shadowcat"
$repoUrl = "https://github.com/thanakorn30006/shadowcat.git"

if (Test-Path "$targetDir\.git") {
    Write-Host "[*] Existing installation found at $targetDir. Updating..." -ForegroundColor Yellow
    Set-Location $targetDir
    git pull --quiet
} else {
    Write-Host "[*] Downloading SHADOW CAT into $targetDir..." -ForegroundColor Cyan
    if (Get-Command git -ErrorAction SilentlyContinue) {
        git clone $repoUrl $targetDir --quiet
        Set-Location $targetDir
    } else {
        # Fallback to direct Zip download if git is not installed
        $zipUrl = "https://github.com/thanakorn30006/shadowcat/archive/refs/heads/main.zip"
        $zipDest = Join-Path $HOME "shadowcat.zip"
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipDest
        Expand-Archive -Path $zipDest -DestinationPath $HOME -Force
        Rename-Item -Path (Join-Path $HOME "shadowcat-main") -NewName "shadowcat" -Force
        Remove-Item $zipDest -Force
        Set-Location $targetDir
    }
}

# 3. Create Virtualenv & Install Requirements
Write-Host "[*] Setting up Python virtual environment..." -ForegroundColor Cyan
$venvDir = Join-Path $targetDir "backend\venv"
if (-not (Test-Path $venvDir)) {
    & $pythonCmd -m venv $venvDir
}

$venvPython = Join-Path $venvDir "Scripts\python.exe"
$reqFile = Join-Path $targetDir "backend\requirements.txt"

Write-Host "[*] Installing dependencies..." -ForegroundColor Cyan
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r $reqFile --quiet

# 4. Create Global Runner (.cmd script)
$binDir = Join-Path $HOME "AppData\Local\Microsoft\WindowsApps"
$batchFile = Join-Path $binDir "shadowcat.cmd"
@"
@echo off
cd /d "$targetDir\backend"
"$venvPython" -m uvicorn main:app --host 0.0.0.0 --port 8000
"@ | Out-File -FilePath $batchFile -Encoding ascii -Force

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "[OK] SHADOW CAT Installation Complete on Windows!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "You can now run 'shadowcat' from any PowerShell or CMD window." -ForegroundColor Yellow
Write-Host "Launching platform at http://localhost:8000..." -ForegroundColor Cyan

# Launch server in background and open browser
Start-Process $venvPython -ArgumentList "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000" -WorkingDirectory (Join-Path $targetDir "backend")
Start-Sleep -Seconds 2
Start-Process "http://localhost:8000"
