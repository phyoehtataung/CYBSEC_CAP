$ErrorActionPreference = "Stop"
$script = Join-Path $PSScriptRoot "fetch-lab-sources.py"
python $script @args
