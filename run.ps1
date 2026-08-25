$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path "backend\.venv")) {
  python -m venv backend\.venv
}
& backend\.venv\Scripts\python -m pip install -r backend\requirements.txt
if (-not (Test-Path "frontend\node_modules")) {
  npm install --prefix frontend
}

Write-Host "Starting WebSET API on http://127.0.0.1:8000"
Start-Process -FilePath "backend\.venv\Scripts\python.exe" -ArgumentList "run.py" -WorkingDirectory $PSScriptRoot
Start-Sleep -Seconds 2
Write-Host "Starting dashboard on http://127.0.0.1:5173"
npm run dev --prefix frontend
